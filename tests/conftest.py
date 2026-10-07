import os
import sys
import tempfile

# main.py는 import 시점에 init_db()를 실행하므로, 먼저 임시 DB 경로를 지정해 저장소의 service.db를 건드리지 않는다.
os.environ.setdefault("DB_FILE", os.path.join(tempfile.mkdtemp(), "import.db"))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
