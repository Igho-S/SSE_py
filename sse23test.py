import time
import random
import string
import statistics
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from typing import List, Dict, Any
import json
import os
import uuid

class SSESystemUnderTest:
    """Wrapper for your SSE system with proper connection management"""
    def __init__(self, server_url: str, user_id: str, passphrase: str):
        self.server_url = server_url
        self.user_id = user_id
        self.passphrase = passphrase
        self.db_manager = None
        self.sse = None
    
    def setup(self):
        """Setup connection and initialize SSE system"""
        from sse23c import RemoteDatabaseManager, ForwardPrivacySearchableEncryption
        self.db_manager = RemoteDatabaseManager(self.server_url)
        self.db_manager.connect()
        self.sse = ForwardPrivacySearchableEncryption(self.db_manager, self.user_id, self.passphrase)
    
    def teardown(self):
        """Cleanup connection"""
        if self.db_manager:
            self.db_manager.disconnect()
    
    def add_document(self, doc_id: str, content: str, keywords: List[str]):
        if self.sse:
            self.sse.add_document_with_partial_search(doc_id, content, keywords)
        else:
            raise Exception("SSE system not initialized. Call setup() first.")
    
    def search_exact(self, keyword: str):
        if self.sse:
            return self.sse.search_documents(keyword, include_archived=False)
        else:
            raise Exception("SSE system not initialized. Call setup() first.")
    
    def search_partial(self, keyword: str):
        if self.sse:
            return self.sse.partial_search(keyword, include_archived=False)
        else:
            raise Exception("SSE system not initialized. Call setup() first.")
    
    def get_document(self, doc_id: str):
        if self.sse:
            return self.sse.get_document(doc_id)
        else:
            raise Exception("SSE system not initialized. Call setup() first.")
    
    def cleanup_database(self):
        """Clean up all test data to avoid duplicate errors"""
        if not self.sse or not self.db_manager:
            return
        try:
            self.db_manager.start_transaction()
            self.db_manager.execute_query(
                "DELETE FROM keyword_trigrams WHERE doc_id IN (SELECT doc_id FROM document_access WHERE user_id = ?)",
                (self.user_id,)
            )
            self.db_manager.execute_query(
                "DELETE FROM document_access WHERE user_id = ?",
                (self.user_id,)
            )
            self.db_manager.execute_query(
                "DELETE FROM documents WHERE session_id IN (SELECT session_id FROM sessions WHERE user_id = ?)",
                (self.user_id,)
            )
            self.db_manager.execute_query(
                "DELETE FROM sessions WHERE user_id = ?",
                (self.user_id,)
            )
            self.db_manager.execute_query(
                "DELETE FROM users WHERE user_id = ?",
                (self.user_id,)
            )
            self.db_manager.commit()
            print("Database cleanup completed.")
        except Exception as e:
            self.db_manager.rollback()
            print(f"Warning: Cleanup failed: {e}")

class PerformanceTestSuite:
    def __init__(self):
        self.results = {}
        self.test_data = {}
        
    def generate_test_data(self, num_documents: int, content_length: int = 1000, run_id: int = 0):
        """Generate test documents with globally unique IDs"""
        documents = []
        keywords_pool = [
            'technology', 'science', 'mathematics', 'computer', 'algorithm',
            'encryption', 'security', 'privacy', 'database', 'network',
            'software', 'hardware', 'protocol', 'authentication', 'cryptography'
        ]
        unique_run_id = f"{run_id}_{str(uuid.uuid4())[:8]}"  # Ensure global uniqueness of run
        for i in range(num_documents):
            doc_id = f"doc_run{unique_run_id}_{i:06d}"
            content = ''.join(random.choices(string.ascii_letters + string.digits + ' ', k=content_length))
            num_keywords = random.randint(3, 5)
            doc_keywords = random.sample(keywords_pool, num_keywords)
            documents.append({
                'doc_id': doc_id,
                'content': content,
                'keywords': doc_keywords
            })
        self.test_data['documents'] = documents
        self.test_data['keywords_pool'] = keywords_pool
        return documents
    
    def measure_throughput(self, operations: List[callable], num_runs: int = 10) -> Dict[str, Any]:
        """Measure throughput of operations with error handling"""
        times = []
        for run in range(num_runs):
            print(f"  Run {run + 1}/{num_runs}...")
            try:
                start_time = time.time()
                for operation in operations:
                    operation()
                end_time = time.time()
                elapsed = end_time - start_time
                times.append(elapsed)
                print(f"  Completed in {elapsed:.2f} seconds")
            except Exception as e:
                print(f"  Run {run + 1} failed: {e}")
                continue
        if times:
            throughput = len(operations) / statistics.mean(times)
        else:
            throughput = 0
        return {
            'mean_time': statistics.mean(times) if times else 0,
            'std_time': statistics.stdev(times) if len(times) > 1 else 0,
            'throughput_ops_sec': throughput,
            'all_times': times
        }
    
    def test_document_insertion(self, sse_system, num_documents: int, num_runs: int = 5, run_id: int = 0):
        """Test document insertion performance with unique document IDs"""
        print(f"Testing document insertion with {num_documents} documents (Run {run_id})...")
        documents = self.generate_test_data(num_documents, run_id=run_id)
        
        def insertion_operations():
            for i, doc in enumerate(documents):
                try:
                    sse_system.add_document(doc['doc_id'], doc['content'], doc['keywords'])
                    if (i + 1) % 10 == 0:
                        print(f"    Inserted {i + 1}/{num_documents} documents")
                except Exception as e:
                    print(f"Error inserting document {doc['doc_id']}: {e}")
                    raise
        results = self.measure_throughput([insertion_operations], num_runs)
        self.results['insertion'] = {
            'num_documents': num_documents,
            'run_id': run_id,
            **results
        }
        return results
    
    def test_search_performance(self, sse_system, num_searches: int = 100, num_runs: int = 10):
        """Test search performance"""
        print(f"Testing search performance with {num_searches} searches...")
        keywords_pool = self.test_data['keywords_pool']
        
        def search_operations():
            for i in range(num_searches):
                keyword = random.choice(keywords_pool)
                results = sse_system.search_exact(keyword)
                if (i + 1) % 5 == 0:
                    print(f"    Completed {i + 1}/{num_searches} searches")
        results = self.measure_throughput([search_operations], num_runs)
        self.results['search_exact'] = {
            'num_searches': num_searches,
            **results
        }
        
        print(f"Testing partial search performance with {num_searches} searches...")
        partial_keywords = ['tech', 'sci', 'math', 'comp', 'alg']
        
        def partial_search_operations():
            for i in range(num_searches):
                keyword = random.choice(partial_keywords)
                results = sse_system.search_partial(keyword)
                if (i + 1) % 5 == 0:
                    print(f"    Completed {i + 1}/{num_searches} partial searches")
        partial_results = self.measure_throughput([partial_search_operations], num_runs)
        self.results['search_partial'] = {
            'num_searches': num_searches,
            **partial_results
        }
        return results, partial_results
    
    def test_scalability(self, sse_system, max_documents: int = 1000, step: int = 100, run_id: int = 0):
        """Test how performance scales with number of documents"""
        print("Testing scalability...")
        scalability_results = {}
        current_doc_count = 0
        
        for num_docs in range(step, max_documents + 1, step):
            print(f"Testing with {num_docs} documents...")
            docs_to_add = num_docs - current_doc_count
            documents = self.generate_test_data(docs_to_add, run_id=run_id)
            for i, doc in enumerate(documents):
                sse_system.add_document(doc['doc_id'], doc['content'], doc['keywords'])
                if (i + 1) % 10 == 0:
                    print(f"    Inserted {i + 1}/{docs_to_add} documents")
            current_doc_count = num_docs
            keywords_pool = self.test_data['keywords_pool']
            search_times = []
            for i in range(10):
                keyword = random.choice(keywords_pool)
                start_time = time.time()
                sse_system.search_exact(keyword)
                end_time = time.time()
                search_times.append(end_time - start_time)
                print(f"    Search {i + 1}/10 completed")
            scalability_results[num_docs] = {
                'mean_search_time': statistics.mean(search_times),
                'std_search_time': statistics.stdev(search_times) if len(search_times) > 1 else 0
            }
        self.results['scalability'] = scalability_results
        return scalability_results
    
    def test_session_management(self, sse_system, num_sessions: int = 10, run_id: int = 0):
        """Test session management performance"""
        print(f"Testing session management with {num_sessions} sessions...")
        session_times = []
        for i in range(num_sessions):
            print(f"  Session {i + 1}/{num_sessions}...")
            documents = self.generate_test_data(10, run_id=run_id*100 + i)
            for doc in documents:
                sse_system.add_document(doc['doc_id'], doc['content'], doc['keywords'])
            start_time = time.time()
            sse_system.sse.end_current_session()
            end_time = time.time()
            session_time = end_time - start_time
            session_times.append(session_time)
            print(f"  Session change completed in {session_time:.2f} seconds")
        self.results['session_management'] = {
            'num_sessions': num_sessions,
            'mean_time_per_session': statistics.mean(session_times),
            'std_time': statistics.stdev(session_times) if len(session_times) > 1 else 0
        }
        return session_times
    
    def run_comprehensive_test(self, sse_system, test_scales: List[int] = [50]):
        """Run comprehensive performance test suite with proper cleanup"""
        print("Starting comprehensive performance test...")
        all_results = {}
        run_id = 0
        for scale in test_scales:
            run_id += 1
            print(f"\n=== Testing at scale: {scale} documents (Run {run_id}) ===")
            print("Cleaning up previous test data...")
            sse_system.cleanup_database()
            print("Reinitializing SSE system...")
            sse_system.teardown()
            sse_system.setup()
            print("\n--- Testing Document Insertion ---")
            insertion_results = self.test_document_insertion(sse_system, scale, num_runs=2, run_id=run_id)
            print("\n--- Testing Search Performance ---")
            search_results, partial_results = self.test_search_performance(sse_system, 5, num_runs=3)
            print("\n--- Testing Scalability ---")
            scalability_results = self.test_scalability(sse_system, scale, max(scale//2, 50), run_id=run_id)
            all_results[scale] = {
                'insertion': insertion_results,
                'search_exact': search_results,
                'search_partial': partial_results,
                'scalability': scalability_results
            }
        print("\n--- Testing Session Management ---")
        session_results = self.test_session_management(sse_system, 3, run_id=run_id+1)
        all_results['session_management'] = session_results
        self.results['comprehensive'] = all_results
        return all_results
    
    def generate_report(self, output_file: str = "performance_report.json"):
        """Generate detailed performance report"""
        report = {
            'timestamp': time.time(),
            'test_environment': {
                'python_version': os.sys.version,
                'system': os.name
            },
            'results': self.results
        }
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"Performance report saved to {output_file}")
        return report
    
    def plot_results(self):
        """Generate visualizations of performance results"""
        if not self.results or 'comprehensive' not in self.results:
            print("No results to plot. Run tests first.")
            return
        os.makedirs('plots', exist_ok=True)
        plt.figure(figsize=(12, 8))
        scales = []
        insertion_times = []
        search_times = []
        for scale, results in self.results['comprehensive'].items():
            if isinstance(scale, int):
                scales.append(scale)
                insertion_times.append(results['insertion']['mean_time'] if 'insertion' in results else 0)
                search_time = results['search_exact'].get('mean_search_time', results['search_exact']['mean_time'] if 'search_exact' in results else 0)
                search_times.append(search_time)
        if scales:
            plt.subplot(2, 2, 1)
            plt.plot(scales, insertion_times, 'bo-', markersize=8, linewidth=2)
            plt.xlabel('Number of Documents')
            plt.ylabel('Total Insertion Time (seconds)')
            plt.title('Document Insertion Performance')
            plt.grid(True, alpha=0.3)
            plt.subplot(2, 2, 2)
            plt.plot(scales, search_times, 'ro-', markersize=8, linewidth=2)
            plt.xlabel('Number of Documents')
            plt.ylabel('Average Search Time (seconds)')
            plt.title('Search Performance vs Database Size')
            plt.grid(True, alpha=0.3)
        if 'scalability' in self.results and self.results['scalability']:
            scales = list(self.results['scalability'].keys())
            search_times = [self.results['scalability'][s]['mean_search_time'] for s in scales]
            plt.subplot(2, 2, 3)
            plt.plot(scales, search_times, 'go-', markersize=8, linewidth=2)
            plt.xlabel('Number of Documents')
            plt.ylabel('Mean Search Time (seconds)')
            plt.title('Search Scalability')
            plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig('plots/performance_results.png', dpi=300, bbox_inches='tight')
        plt.show()

def main():
    """Main function to run performance tests"""
    SERVER_URL = "http://194.58.40.216:9999/"
    unique_id = str(uuid.uuid4())[:8]
    USER_ID = f"perf_test_{unique_id}"
    PASSPHRASE = "test_passphrase_123"
    
    print("=== SSE Performance Test ===")
    print(f"Server URL: {SERVER_URL}")
    print(f"User ID: {USER_ID}")
    print("=" * 40)
    
    test_suite = PerformanceTestSuite()
    sse_system = SSESystemUnderTest(SERVER_URL, USER_ID, PASSPHRASE)
    
    try:
        print("Cleaning up database before test...")
        sse_system.setup()
        sse_system.cleanup_database()
        sse_system.teardown()
        print("Setting up connection and initializing SSE system...")
        sse_system.setup()
        
        print("\n=== Running Quick Verification ===")
        test_suite.test_document_insertion(sse_system, 3, num_runs=1, run_id=0)
        print("Quick verification passed!")
        
        print("\n=== Running Comprehensive Tests ===")
        results = test_suite.run_comprehensive_test(sse_system, test_scales=[5])
        
        report = test_suite.generate_report()
        test_suite.plot_results()
        
        print("\n=== PERFORMANCE TEST SUMMARY ===")
        for scale, scale_results in report['results']['comprehensive'].items():
            if isinstance(scale, int):
                print(f"\nScale: {scale} documents")
                print(f"Insertion throughput: {scale_results['insertion']['throughput_ops_sec']:.2f} ops/sec")
                search_time = scale_results['search_exact'].get('mean_search_time', scale_results['search_exact']['mean_time'])
                print(f"Search latency: {search_time*1000:.2f} ms")
        
    except Exception as e:
        print(f"Error during performance testing: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("\nCleaning up...")
        sse_system.cleanup_database()
        sse_system.teardown()
        print("Test completed.")

if __name__ == "__main__":
    main()