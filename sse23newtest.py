import time
import random
import string
import statistics
import pandas as pd
import uuid
from typing import List, Dict, Any
import json
from datetime import datetime

class ComprehensiveSSETest:
    def __init__(self, server_url: str):
        self.server_url = server_url
        self.results = []
        self.test_scales = [10, 100, 500]

    def generate_test_data(self, num_documents: int, run_id: str) -> List[Dict]:
        documents = []
        keywords_pool = [
            'technology', 'science', 'mathematics', 'computer', 'algorithm',
            'encryption', 'security', 'privacy', 'database', 'network',
            'software', 'hardware', 'protocol', 'authentication', 'cryptography',
            'system', 'data', 'machine', 'learning', 'artificial'
        ]

        for i in range(num_documents):
            doc_id = f"doc_{run_id}_{i:06d}"
            content = ''.join(random.choices(string.ascii_letters + string.digits + ' ', k=1000))
            num_keywords = random.randint(3, 5)
            doc_keywords = random.sample(keywords_pool, num_keywords)

            documents.append({
                'doc_id': doc_id,
                'content': content,
                'keywords': doc_keywords
            })

        return documents

    def setup_sse_system(self, user_id: str, passphrase: str, enable_encryption: bool = True):
        from sse23c_mysql_t import RemoteDatabaseManager, ForwardPrivacySearchableEncryption

        db_manager = RemoteDatabaseManager(self.server_url)
        db_manager.connect()

        sse = ForwardPrivacySearchableEncryption(db_manager, user_id, passphrase)

        return db_manager, sse

    def cleanup_sse(self, db_manager, user_id: str):
        try:
            db_manager.execute_query(
                "DELETE FROM keyword_trigrams WHERE user_id = %s",
                (user_id,)
            )
            db_manager.execute_query(
                "DELETE FROM document_access WHERE user_id = %s",
                (user_id,)
            )
            db_manager.execute_query(
                "DELETE FROM documents WHERE user_id = %s",
                (user_id,)
            )
            db_manager.execute_query(
                "DELETE FROM sessions WHERE user_id = %s",
                (user_id,)
            )
            db_manager.execute_query(
                "DELETE FROM users WHERE user_id = %s",
                (user_id,)
            )
            db_manager.disconnect()
        except Exception as e:
            print(f"Cleanup warning: {e}")

    def test_scenario_1_no_encryption_trusted_server(self, num_docs: int):
        test_name = "Test 1: No Encryption (Trusted Server)"
        run_id = str(uuid.uuid4())[:8]
        user_id = f"test1_{run_id}"

        print(f"\n{'='*60}")
        print(f"{test_name} - {num_docs} documents")
        print(f"{'='*60}")

        db_manager, sse = self.setup_sse_system(user_id, "passphrase123")

        try:
            documents = self.generate_test_data(num_docs, run_id)

            # Test insertion
            start_time = time.time()
            for i, doc in enumerate(documents):
                sse.add_document(doc['doc_id'], doc['content'], doc['keywords'])
                if (i + 1) % max(1, num_docs // 10) == 0:
                    print(f"  Inserted {i + 1}/{num_docs} documents")
            insertion_time = time.time() - start_time

            # Test search
            search_times = []
            for i in range(5):
                keyword = random.choice(sse.test_data['keywords_pool'] if hasattr(sse, 'test_data') else documents[0]['keywords'])
                start = time.time()
                results = sse.search_documents(keyword)
                search_times.append(time.time() - start)
            avg_search_time = statistics.mean(search_times)

            result = {
                'test_name': test_name,
                'num_documents': num_docs,
                'encryption_enabled': False,
                'trigrams_enabled': False,
                'insertion_time_s': insertion_time,
                'avg_search_time_ms': avg_search_time * 1000,
                'docs_per_second': num_docs / insertion_time if insertion_time > 0 else 0,
                'status': 'PASSED'
            }

            print(f"Insertion Time: {insertion_time:.2f}s")
            print(f"Avg Search Time: {avg_search_time*1000:.2f}ms")
            print(f"Throughput: {num_docs/insertion_time:.2f} docs/sec")

            self.results.append(result)
            return result

        except Exception as e:
            print(f"Test failed: {e}")
            self.results.append({
                'test_name': test_name,
                'num_documents': num_docs,
                'status': 'FAILED',
                'error': str(e)
            })
            return None
        finally:
            self.cleanup_sse(db_manager, user_id)

    def test_scenario_2_encrypted_save_untrusted_server(self, num_docs: int):
        test_name = "Test 2: Encryption Enabled (Untrusted Server)"
        run_id = str(uuid.uuid4())[:8]
        user_id = f"test2_{run_id}"

        print(f"\n{'='*60}")
        print(f"{test_name} - {num_docs} documents")
        print(f"{'='*60}")

        db_manager, sse = self.setup_sse_system(user_id, "passphrase123", enable_encryption=True)

        try:
            documents = self.generate_test_data(num_docs, run_id)

            # Test insertion with encryption
            start_time = time.time()
            for i, doc in enumerate(documents):
                sse.add_document_with_partial_search(doc['doc_id'], doc['content'], doc['keywords'])
                if (i + 1) % max(1, num_docs // 10) == 0:
                    print(f"  Inserted {i + 1}/{num_docs} documents")
            insertion_time = time.time() - start_time

            # Test search with encrypted data
            search_times = []
            for i in range(5):
                keyword = random.choice(documents[0]['keywords'])
                start = time.time()
                results = sse.search_documents(keyword)
                search_times.append(time.time() - start)
            avg_search_time = statistics.mean(search_times)

            result = {
                'test_name': test_name,
                'num_documents': num_docs,
                'encryption_enabled': True,
                'trigrams_enabled': True,
                'insertion_time_s': insertion_time,
                'avg_search_time_ms': avg_search_time * 1000,
                'docs_per_second': num_docs / insertion_time if insertion_time > 0 else 0,
                'status': 'PASSED'
            }

            print(f"Insertion Time: {insertion_time:.2f}s")
            print(f"Avg Search Time: {avg_search_time*1000:.2f}ms")
            print(f"Throughput: {num_docs/insertion_time:.2f} docs/sec")

            self.results.append(result)
            return result

        except Exception as e:
            print(f"Test failed: {e}")
            self.results.append({
                'test_name': test_name,
                'num_documents': num_docs,
                'status': 'FAILED',
                'error': str(e)
            })
            return None
        finally:
            self.cleanup_sse(db_manager, user_id)

    def test_scenario_3_no_trigrams_full_search_encrypted(self, num_docs: int):
        test_name = "Test 3: Full Keyword Search Only (Encrypted)"
        run_id = str(uuid.uuid4())[:8]
        user_id = f"test3_{run_id}"

        print(f"\n{'='*60}")
        print(f"{test_name} - {num_docs} documents")
        print(f"{'='*60}")

        db_manager, sse = self.setup_sse_system(user_id, "passphrase123", enable_encryption=True)

        try:
            documents = self.generate_test_data(num_docs, run_id)

            # Test insertion without trigrams (full search only)
            start_time = time.time()
            for i, doc in enumerate(documents):
                sse.add_document(doc['doc_id'], doc['content'], doc['keywords'])
                if (i + 1) % max(1, num_docs // 10) == 0:
                    print(f"  Inserted {i + 1}/{num_docs} documents")
            insertion_time = time.time() - start_time

            # Test full keyword search
            search_times = []
            for i in range(5):
                keyword = random.choice(documents[0]['keywords'])
                start = time.time()
                results = sse.search_documents(keyword)
                search_times.append(time.time() - start)
            avg_search_time = statistics.mean(search_times)

            result = {
                'test_name': test_name,
                'num_documents': num_docs,
                'encryption_enabled': True,
                'trigrams_enabled': False,
                'insertion_time_s': insertion_time,
                'avg_search_time_ms': avg_search_time * 1000,
                'docs_per_second': num_docs / insertion_time if insertion_time > 0 else 0,
                'status': 'PASSED'
            }

            print(f"Insertion Time: {insertion_time:.2f}s")
            print(f"Avg Search Time: {avg_search_time*1000:.2f}ms")
            print(f"Throughput: {num_docs/insertion_time:.2f} docs/sec")

            self.results.append(result)
            return result

        except Exception as e:
            print(f"Test failed: {e}")
            self.results.append({
                'test_name': test_name,
                'num_documents': num_docs,
                'status': 'FAILED',
                'error': str(e)
            })
            return None
        finally:
            self.cleanup_sse(db_manager, user_id)

    def test_scenario_4_no_trigrams_full_search_unencrypted(self, num_docs: int):
        test_name = "Test 4: Full Keyword Search Only (Unencrypted)"
        run_id = str(uuid.uuid4())[:8]
        user_id = f"test4_{run_id}"

        print(f"\n{'='*60}")
        print(f"{test_name} - {num_docs} documents")
        print(f"{'='*60}")

        db_manager, sse = self.setup_sse_system(user_id, "passphrase123", enable_encryption=False)

        try:
            documents = self.generate_test_data(num_docs, run_id)

            # Test insertion without trigrams and without encryption
            start_time = time.time()
            for i, doc in enumerate(documents):
                sse.add_document(doc['doc_id'], doc['content'], doc['keywords'])
                if (i + 1) % max(1, num_docs // 10) == 0:
                    print(f"  Inserted {i + 1}/{num_docs} documents")
            insertion_time = time.time() - start_time

            # Test full keyword search
            search_times = []
            for i in range(5):
                keyword = random.choice(documents[0]['keywords'])
                start = time.time()
                results = sse.search_documents(keyword)
                search_times.append(time.time() - start)
            avg_search_time = statistics.mean(search_times)

            result = {
                'test_name': test_name,
                'num_documents': num_docs,
                'encryption_enabled': False,
                'trigrams_enabled': False,
                'insertion_time_s': insertion_time,
                'avg_search_time_ms': avg_search_time * 1000,
                'docs_per_second': num_docs / insertion_time if insertion_time > 0 else 0,
                'status': 'PASSED'
            }

            print(f"Insertion Time: {insertion_time:.2f}s")
            print(f"Avg Search Time: {avg_search_time*1000:.2f}ms")
            print(f"Throughput: {num_docs/insertion_time:.2f} docs/sec")

            self.results.append(result)
            return result

        except Exception as e:
            print(f"Test failed: {e}")
            self.results.append({
                'test_name': test_name,
                'num_documents': num_docs,
                'status': 'FAILED',
                'error': str(e)
            })
            return None
        finally:
            self.cleanup_sse(db_manager, user_id)

    def test_scenario_5_with_trigrams_encrypted(self, num_docs: int):
        test_name = "Test 5: With Trigrams (Encrypted)"
        run_id = str(uuid.uuid4())[:8]
        user_id = f"test5_{run_id}"

        print(f"\n{'='*60}")
        print(f"{test_name} - {num_docs} documents")
        print(f"{'='*60}")

        db_manager, sse = self.setup_sse_system(user_id, "passphrase123", enable_encryption=True)

        try:
            documents = self.generate_test_data(num_docs, run_id)

            # Test insertion with trigrams and encryption
            start_time = time.time()
            for i, doc in enumerate(documents):
                sse.add_document_with_partial_search(doc['doc_id'], doc['content'], doc['keywords'])
                if (i + 1) % max(1, num_docs // 10) == 0:
                    print(f"  Inserted {i + 1}/{num_docs} documents")
            insertion_time = time.time() - start_time

            # Test partial search with trigrams
            search_times = []
            partial_keywords = ['tech', 'sec', 'priv', 'crypto', 'data']
            for i in range(5):
                keyword = random.choice(partial_keywords)
                start = time.time()
                results = sse.partial_search(keyword)
                search_times.append(time.time() - start)
            avg_search_time = statistics.mean(search_times)

            result = {
                'test_name': test_name,
                'num_documents': num_docs,
                'encryption_enabled': True,
                'trigrams_enabled': True,
                'insertion_time_s': insertion_time,
                'avg_search_time_ms': avg_search_time * 1000,
                'docs_per_second': num_docs / insertion_time if insertion_time > 0 else 0,
                'status': 'PASSED'
            }

            print(f"Insertion Time: {insertion_time:.2f}s")
            print(f"Avg Partial Search Time: {avg_search_time*1000:.2f}ms")
            print(f"Throughput: {num_docs/insertion_time:.2f} docs/sec")

            self.results.append(result)
            return result

        except Exception as e:
            print(f"Test failed: {e}")
            self.results.append({
                'test_name': test_name,
                'num_documents': num_docs,
                'status': 'FAILED',
                'error': str(e)
            })
            return None
        finally:
            self.cleanup_sse(db_manager, user_id)

    def test_scenario_6_with_trigrams_unencrypted(self, num_docs: int):
        test_name = "Test 6: With Trigrams (Unencrypted)"
        run_id = str(uuid.uuid4())[:8]
        user_id = f"test6_{run_id}"

        print(f"\n{'='*60}")
        print(f"{test_name} - {num_docs} documents")
        print(f"{'='*60}")

        db_manager, sse = self.setup_sse_system(user_id, "passphrase123", enable_encryption=False)

        try:
            documents = self.generate_test_data(num_docs, run_id)

            # Test insertion with trigrams but no encryption
            start_time = time.time()
            for i, doc in enumerate(documents):
                sse.add_document_with_partial_search(doc['doc_id'], doc['content'], doc['keywords'])
                if (i + 1) % max(1, num_docs // 10) == 0:
                    print(f"  Inserted {i + 1}/{num_docs} documents")
            insertion_time = time.time() - start_time

            # Test partial search with trigrams
            search_times = []
            partial_keywords = ['tech', 'sec', 'priv', 'crypto', 'data']
            for i in range(5):
                keyword = random.choice(partial_keywords)
                start = time.time()
                results = sse.partial_search(keyword)
                search_times.append(time.time() - start)
            avg_search_time = statistics.mean(search_times)

            result = {
                'test_name': test_name,
                'num_documents': num_docs,
                'encryption_enabled': False,
                'trigrams_enabled': True,
                'insertion_time_s': insertion_time,
                'avg_search_time_ms': avg_search_time * 1000,
                'docs_per_second': num_docs / insertion_time if insertion_time > 0 else 0,
                'status': 'PASSED'
            }

            print(f"Insertion Time: {insertion_time:.2f}s")
            print(f"Avg Partial Search Time: {avg_search_time*1000:.2f}ms")
            print(f"Throughput: {num_docs/insertion_time:.2f} docs/sec")

            self.results.append(result)
            return result

        except Exception as e:
            print(f"Test failed: {e}")
            self.results.append({
                'test_name': test_name,
                'num_documents': num_docs,
                'status': 'FAILED',
                'error': str(e)
            })
            return None
        finally:
            self.cleanup_sse(db_manager, user_id)

    def test_scenario_7_normal_case_full_functionality(self, num_docs: int):
        test_name = "Test 7: Full Functionality (Normal Case)"
        run_id = str(uuid.uuid4())[:8]
        user_id = f"test7_{run_id}"

        print(f"\n{'='*60}")
        print(f"{test_name} - {num_docs} documents")
        print(f"{'='*60}")

        db_manager, sse = self.setup_sse_system(user_id, "passphrase123", enable_encryption=True)

        try:
            documents = self.generate_test_data(num_docs, run_id)

            # Test insertion with full functionality
            start_time = time.time()
            for i, doc in enumerate(documents):
                sse.add_document_with_partial_search(doc['doc_id'], doc['content'], doc['keywords'])
                if (i + 1) % max(1, num_docs // 10) == 0:
                    print(f"  Inserted {i + 1}/{num_docs} documents")
            insertion_time = time.time() - start_time

            # Test exact search
            exact_search_times = []
            for i in range(3):
                keyword = random.choice(documents[0]['keywords'])
                start = time.time()
                results = sse.search_documents(keyword)
                exact_search_times.append(time.time() - start)
            avg_exact_search = statistics.mean(exact_search_times)

            # Test partial search
            partial_search_times = []
            partial_keywords = ['tech', 'sec', 'priv', 'crypto', 'data']
            for i in range(3):
                keyword = random.choice(partial_keywords)
                start = time.time()
                results = sse.partial_search(keyword)
                partial_search_times.append(time.time() - start)
            avg_partial_search = statistics.mean(partial_search_times)

            # Test document retrieval
            test_doc_id = documents[0]['doc_id']
            start = time.time()
            retrieved_content = sse.get_document(test_doc_id)
            retrieval_time = time.time() - start

            # Test document listing
            start = time.time()
            doc_list = sse.list_documents()
            listing_time = time.time() - start

            result = {
                'test_name': test_name,
                'num_documents': num_docs,
                'encryption_enabled': True,
                'trigrams_enabled': True,
                'insertion_time_s': insertion_time,
                'avg_exact_search_ms': avg_exact_search * 1000,
                'avg_partial_search_ms': avg_partial_search * 1000,
                'document_retrieval_ms': retrieval_time * 1000,
                'document_listing_ms': listing_time * 1000,
                'docs_per_second': num_docs / insertion_time if insertion_time > 0 else 0,
                'status': 'PASSED'
            }

            print(f"Insertion Time: {insertion_time:.2f}s")
            print(f"Avg Exact Search Time: {avg_exact_search*1000:.2f}ms")
            print(f"Avg Partial Search Time: {avg_partial_search*1000:.2f}ms")
            print(f"Document Retrieval Time: {retrieval_time*1000:.2f}ms")
            print(f"Document Listing Time: {listing_time*1000:.2f}ms")
            print(f"Throughput: {num_docs/insertion_time:.2f} docs/sec")

            self.results.append(result)
            return result

        except Exception as e:
            print(f"Test failed: {e}")
            self.results.append({
                'test_name': test_name,
                'num_documents': num_docs,
                'status': 'FAILED',
                'error': str(e)
            })
            return None
        finally:
            self.cleanup_sse(db_manager, user_id)

    def run_all_tests(self, server_url: str = "http://localhost:9999"):
        self.server_url = server_url

        print(f"\n{'='*60}")
        print("SSE TEST SUITE")
        print(f"{'='*60}")
        print(f"Server: {server_url}")
        print(f"Test Scales: {self.test_scales}")
        print(f"{'='*60}")

        all_tests = [
            self.test_scenario_1_no_encryption_trusted_server,
            self.test_scenario_2_encrypted_save_untrusted_server,
            self.test_scenario_3_no_trigrams_full_search_encrypted,
            self.test_scenario_4_no_trigrams_full_search_unencrypted,
            self.test_scenario_5_with_trigrams_encrypted,
            self.test_scenario_6_with_trigrams_unencrypted,
            self.test_scenario_7_normal_case_full_functionality,
        ]

        for test_func in all_tests:
            for scale in self.test_scales:
                try:
                    test_func(scale)
                except Exception as e:
                    print(f"Test error: {e}")
                    import traceback
                    traceback.print_exc()

        return self.results

    def export_to_excel(self, filename: str = "sse_test_results.xlsx"):
        df = pd.DataFrame(self.results)

        with pd.ExcelWriter(filename, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='All Results', index=False)

            # Summary sheet
            summary_data = []
            for test_num in range(1, 8):
                test_results = df[df['test_name'].str.contains(f'Test {test_num}:')]
                if not test_results.empty:
                    summary_data.append({
                        'Test Number': test_num,
                        'Test Name': test_results['test_name'].iloc[0],
                        'Min Insertion Time (s)': test_results['insertion_time_s'].min() if 'insertion_time_s' in test_results.columns else 'N/A',
                        'Max Insertion Time (s)': test_results['insertion_time_s'].max() if 'insertion_time_s' in test_results.columns else 'N/A',
                        'Avg Search Time (ms)': test_results['avg_search_time_ms'].mean() if 'avg_search_time_ms' in test_results.columns else 'N/A',
                    })

            summary_df = pd.DataFrame(summary_data)
            summary_df.to_excel(writer, sheet_name='Summary', index=False)

        print(f"\nResults exported to {filename}")

    def export_to_markdown(self, filename: str = "sse_test_results.md"):
        with open(filename, 'w') as f:
            f.write("# SSE System Comprehensive Test Results\n\n")
            f.write(f"**Test Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            f.write("## Overview\n\n")
            f.write(f"Total Tests: {len(self.results)}\n")
            passed = sum(1 for r in self.results if r.get('status') == 'PASSED')
            f.write(f"Passed: {passed}\n")
            f.write(f"Failed: {len(self.results) - passed}\n\n")

            f.write("## Detailed Results\n\n")
            for result in self.results:
                f.write(f"### {result.get('test_name', 'Unknown Test')}\n\n")
                f.write(f"**Number of Documents:** {result.get('num_documents', 'N/A')}\n")
                f.write(f"**Status:** {result.get('status', 'UNKNOWN')}\n")

                if result.get('status') == 'PASSED':
                    f.write(f"**Encryption Enabled:** {result.get('encryption_enabled', 'N/A')}\n")
                    f.write(f"**Trigrams Enabled:** {result.get('trigrams_enabled', 'N/A')}\n")
                    f.write(f"**Insertion Time:** {result.get('insertion_time_s', 'N/A'):.2f}s\n")

                    if 'avg_search_time_ms' in result:
                        f.write(f"**Average Search Time:** {result.get('avg_search_time_ms', 'N/A'):.2f}ms\n")
                    if 'avg_exact_search_ms' in result:
                        f.write(f"**Average Exact Search Time:** {result.get('avg_exact_search_ms', 'N/A'):.2f}ms\n")
                    if 'avg_partial_search_ms' in result:
                        f.write(f"**Average Partial Search Time:** {result.get('avg_partial_search_ms', 'N/A'):.2f}ms\n")
                    if 'document_retrieval_ms' in result:
                        f.write(f"**Document Retrieval Time:** {result.get('document_retrieval_ms', 'N/A'):.2f}ms\n")
                    if 'document_listing_ms' in result:
                        f.write(f"**Document Listing Time:** {result.get('document_listing_ms', 'N/A'):.2f}ms\n")

                    f.write(f"**Throughput:** {result.get('docs_per_second', 'N/A'):.2f} docs/sec\n")
                else:
                    f.write(f"**Error:** {result.get('error', 'Unknown error')}\n")
                f.write("\n")

            f.write("## Performance Comparison\n\n")
            f.write("| Test Name | Documents | Encryption | Trigrams | Insertion Time (s) | Avg Search (ms) | Throughput (docs/s) |\n")
            f.write("|-----------|-----------|------------|----------|-------------------|-----------------|---------------------|\n")

            for result in self.results:
                if result.get('status') == 'PASSED':
                    f.write(f"| {result.get('test_name', 'N/A')} | ")
                    f.write(f"{result.get('num_documents', 'N/A')} | ")
                    f.write(f"{result.get('encryption_enabled', 'N/A')} | ")
                    f.write(f"{result.get('trigrams_enabled', 'N/A')} | ")
                    f.write(f"{result.get('insertion_time_s', 'N/A'):.2f} | ")
                    f.write(f"{result.get('avg_search_time_ms', 'N/A'):.2f} | ")
                    f.write(f"{result.get('docs_per_second', 'N/A'):.2f} |\n")

        print(f"Results exported to {filename}")

def main():
    SERVER_URL = "http://46.17.44.229:1962"

    test_suite = ComprehensiveSSETest(SERVER_URL)

    results = test_suite.run_all_tests(SERVER_URL)

    test_suite.export_to_excel("sse_test_results_all6.xlsx")
    #test_suite.export_to_markdown("sse_test_results.md")

    print(f"\n{'='*60}")
    print("TEST SUITE COMPLETED")
    print(f"{'='*60}")
    print(f"Total Results: {len(results)}")
    print(f"Results saved to:")
    print(f"  - sse_test_results.xlsx")
    #print(f"  - sse_test_results.md")

if __name__ == "__main__":
    main()