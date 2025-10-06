import pymysql
import logging
import base64
from flask import Flask, request, jsonify

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self, host: str, user: str, password: str, db: str):
        self.host = host
        self.user = user
        self.password = password
        self.db = db
        self.conn = None

    def connect(self):
        try:
            self.conn = pymysql.connect(
                host=self.host,
                user=self.user,
                password=self.password,
                db=self.db,
                cursorclass=pymysql.cursors.DictCursor  # Returns results as dicts
            )
            logger.info("Connected to MySQL database.")
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            raise

    def disconnect(self):
        if self.conn:
            self.conn.close()
            logger.info("Disconnected from database.")

    def execute_query(self, query: str, params: tuple = None) -> list | None:
        try:
            with self.conn.cursor() as cursor:
                cursor.execute(query, params or ())
                if query.strip().lower().startswith("select"):
                    results = cursor.fetchall()
                    return results
                else:
                    self.conn.commit()
                    return None
        except Exception as e:
            logger.error(f"Failed to execute query: {e}")
            self.conn.rollback()
            raise

def serialize_value(v):
    if isinstance(v, bytes):
        return {'type': 'bytes', 'value': base64.b64encode(v).decode('utf-8')}
    elif isinstance(v, (int, float, str, type(None))):
        return {'type': 'scalar', 'value': v}
    else:
        return {'type': 'str', 'value': str(v)}

app = Flask(__name__)

db_host = "localhost"
db_user = "apapa"  #current, i use adada
db_password = "ApapaInMississippi@1" #ApapaInMississippi1. for adada
db_name = "sse_db" #ssedb2 for adada

db_manager = DatabaseManager(db_host, db_user, db_password, db_name)
db_manager.connect()

@app.route('/execute_query', methods=['POST'])
def handle_execute_query():
    data = request.json
    query = data['query']
    params_list = data['params']
    params = tuple(deserialize_param(p) for p in params_list)
    try:
        result = db_manager.execute_query(query, params)
        if result is not None:
            serialized_result = [{k: serialize_value(val) for k, val in row.items()} for row in result]
            return jsonify({'result': serialized_result})
        else:
            return jsonify({'result': None})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/start_transaction', methods=['POST'])
def handle_start_transaction():
    try:
        db_manager.conn.begin()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/commit', methods=['POST'])
def handle_commit():
    try:
        db_manager.conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/rollback', methods=['POST'])
def handle_rollback():
    try:
        db_manager.conn.rollback()
        return jupytext({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/connect', methods=['POST'])
def handle_connect():
    try:
        db_manager.connect()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/disconnect', methods=['POST'])
def handle_disconnect():
    db_manager.disconnect()
    return jsonify({'success': True})

def deserialize_param(p):
    if p['type'] == 'bytes':
        return base64.b64decode(p['value'])
    else:
        return p['value']

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=9999, debug=False)