from confluent_kafka import Consumer, Producer, KafkaError
from pyspark.sql import SparkSession
from pyspark.sql.functions import *
from pyspark.sql.types import *
import json
import logging
import threading
from typing import Dict, List, Callable
from datetime import datetime
import queue
import time

class KafkaHandler:
    def __init__(self, config: Dict):
        """Initialize Kafka producer and consumer."""
        self.producer_config = {
            'bootstrap.servers': config.get('bootstrap_servers', 'localhost:9092'),
            'client.id': config.get('client_id', 'network_monitor'),
            'acks': 'all'
        }
        
        self.consumer_config = {
            'bootstrap.servers': config.get('bootstrap_servers', 'localhost:9092'),
            'group.id': config.get('group_id', 'network_monitor_group'),
            'auto.offset.reset': 'earliest',
            'enable.auto.commit': False
        }
        
        self.producer = Producer(self.producer_config)
        self.consumer = Consumer(self.consumer_config)
        self.logger = logging.getLogger(__name__)
        self.running = False
        self.message_queue = queue.Queue()

    def delivery_callback(self, err, msg):
        """Callback for message delivery confirmation."""
        if err:
            self.logger.error(f'Message delivery failed: {err}')
        else:
            self.logger.debug(f'Message delivered to {msg.topic()} [{msg.partition()}]')

    def produce_message(self, topic: str, message: Dict):
        """Produce message to Kafka topic."""
        try:
            message_str = json.dumps(message)
            self.producer.produce(
                topic,
                value=message_str.encode('utf-8'),
                callback=self.delivery_callback
            )
            self.producer.poll(0)
            
        except Exception as e:
            self.logger.error(f'Error producing message: {str(e)}')

    def start_consuming(self, topics: List[str], message_handler: Callable):
        """Start consuming messages from Kafka topics."""
        def consume_loop():
            try:
                self.consumer.subscribe(topics)
                self.running = True
                
                while self.running:
                    msg = self.consumer.poll(1.0)
                    
                    if msg is None:
                        continue
                    
                    if msg.error():
                        if msg.error().code() == KafkaError._PARTITION_EOF:
                            self.logger.debug('Reached end of partition')
                        else:
                            self.logger.error(f'Error: {msg.error()}')
                    else:
                        try:
                            message = json.loads(msg.value().decode('utf-8'))
                            message_handler(message)
                            self.consumer.commit()
                        except json.JSONDecodeError as e:
                            self.logger.error(f'Error decoding message: {str(e)}')
                        except Exception as e:
                            self.logger.error(f'Error processing message: {str(e)}')
                
            except Exception as e:
                self.logger.error(f'Error in consume loop: {str(e)}')
            finally:
                self.consumer.close()
        
        consumer_thread = threading.Thread(target=consume_loop)
        consumer_thread.start()

    def stop_consuming(self):
        """Stop consuming messages."""
        self.running = False

class SparkStreamProcessor:
    def __init__(self, config: Dict):
        """Initialize Spark Streaming session and configuration."""
        self.config = config
        self.spark = None
        self.streaming_query = None
        self.logger = logging.getLogger(__name__)
        
        self.schema = StructType([
            StructField("timestamp", TimestampType(), True),
            StructField("src_ip", StringType(), True),
            StructField("dst_ip", StringType(), True),
            StructField("src_port", IntegerType(), True),
            StructField("dst_port", IntegerType(), True),
            StructField("protocol", StringType(), True),
            StructField("bytes_sent", LongType(), True),
            StructField("bytes_recv", LongType(), True),
            StructField("packets_sent", IntegerType(), True),
            StructField("packets_recv", IntegerType(), True),
            StructField("flags", StringType(), True)
        ])

    def initialize_spark(self):
        """Initialize Spark session with configuration."""
        try:
            self.spark = (SparkSession.builder
                .appName(self.config.get('app_name', 'NetworkMonitor'))
                .config('spark.streaming.stopGracefullyOnShutdown', 'true')
                .config('spark.sql.streaming.schemaInference', 'true')
                .getOrCreate())
            
            self.logger.info("Spark session initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing Spark session: {str(e)}")
            raise

    def create_streaming_dataframe(self, kafka_config: Dict):
        """Create streaming DataFrame from Kafka source."""
        try:
            return (self.spark
                .readStream
                .format("kafka")
                .option("kafka.bootstrap.servers", kafka_config['bootstrap_servers'])
                .option("subscribe", kafka_config['topic'])
                .option("startingOffsets", "latest")
                .load()
                .select(from_json(col("value").cast("string"), self.schema).alias("data"))
                .select("data.*"))
            
        except Exception as e:
            self.logger.error(f"Error creating streaming DataFrame: {str(e)}")
            raise

    def process_stream(self, df, output_path: str):
        """Process streaming data with windowed aggregations."""
        try:
            # Window duration and slide interval
            window_duration = "1 minute"
            slide_interval = "30 seconds"
            
            # Windowed aggregations
            windowed_stats = (df
                .withWatermark("timestamp", "2 minutes")
                .groupBy(
                    window("timestamp", window_duration, slide_interval),
                    "src_ip",
                    "dst_ip"
                )
                .agg(
                    sum("bytes_sent").alias("total_bytes_sent"),
                    sum("bytes_recv").alias("total_bytes_recv"),
                    sum("packets_sent").alias("total_packets_sent"),
                    sum("packets_recv").alias("total_packets_recv"),
                    count("*").alias("flow_count")
                ))
            
            # Calculate rates and statistics
            stats = (windowed_stats
                .withColumn("bytes_per_second", 
                    (col("total_bytes_sent") + col("total_bytes_recv")) / 60)
                .withColumn("packets_per_second",
                    (col("total_packets_sent") + col("total_packets_recv")) / 60))
            
            # Write stream to console and files
            console_query = (stats
                .writeStream
                .outputMode("update")
                .format("console")
                .trigger(processingTime="30 seconds")
                .start())
            
            file_query = (stats
                .writeStream
                .outputMode("append")
                .format("parquet")
                .option("path", output_path)
                .option("checkpointLocation", f"{output_path}/checkpoints")
                .trigger(processingTime="30 seconds")
                .start())
            
            self.streaming_query = console_query
            
            return console_query, file_query
            
        except Exception as e:
            self.logger.error(f"Error processing stream: {str(e)}")
            raise

    def stop_streaming(self):
        """Stop all streaming queries."""
        try:
            if self.streaming_query:
                self.streaming_query.stop()
                self.logger.info("Streaming queries stopped")
        except Exception as e:
            self.logger.error(f"Error stopping streaming queries: {str(e)}")

class StreamProcessor:
    def __init__(self, config: Dict):
        """Initialize stream processing components."""
        self.config = config
        self.kafka_handler = KafkaHandler(config.get('kafka', {}))
        self.spark_processor = SparkStreamProcessor(config.get('spark', {}))
        self.logger = logging.getLogger(__name__)
        
        # Initialize processing components
        self.initialize_components()

    def initialize_components(self):
        """Initialize all streaming components."""
        try:
            # Initialize Spark
            self.spark_processor.initialize_spark()
            self.logger.info("Stream processor initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing stream processor: {str(e)}")
            raise

    def start_processing(self, input_topic: str, output_path: str):
        """Start the stream processing pipeline."""
        try:
            # Create streaming DataFrame
            kafka_config = {
                'bootstrap_servers': self.config['kafka']['bootstrap_servers'],
                'topic': input_topic
            }
            
            streaming_df = self.spark_processor.create_streaming_dataframe(kafka_config)
            
            # Start processing
            console_query, file_query = self.spark_processor.process_stream(
                streaming_df, 
                output_path
            )
            
            self.logger.info("Stream processing started successfully")
            
            return console_query, file_query
            
        except Exception as e:
            self.logger.error(f"Error starting stream processing: {str(e)}")
            raise

    def stop_processing(self):
        """Stop all processing components."""
        try:
            self.kafka_handler.stop_consuming()
            self.spark_processor.stop_streaming()
            self.logger.info("Stream processing stopped")
            
        except Exception as e:
            self.logger.error(f"Error stopping stream processing: {str(e)}")
            raise

if __name__ == "__main__":
    # Example configuration
    config = {
        'kafka': {
            'bootstrap_servers': 'localhost:9092',
            'client_id': 'network_monitor',
            'group_id': 'network_monitor_group'
        },
        'spark': {
            'app_name': 'NetworkMonitor',
            'master': 'local[*]'
        }
    }
    
    # Initialize logging
    logging.basicConfig(level=logging.INFO)
    
    # Create and start processor
    processor = StreamProcessor(config)
    
    try:
        # Start processing
        processor.start_processing(
            input_topic='network_traffic',
            output_path='./output/network_stats'
        )
        
        # Keep the main thread running
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        processor.stop_processing()
        print("\nProcessing stopped") 