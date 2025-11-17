"""
Test setup
"""

from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello():
    return """
    <h1>✅ Flask działa!</h1>
    <p>Środowisko jest gotowe do pracy nad XXE Security Demo</p>
    """

if __name__ == '__main__':
    print("🚀 Starting Flask test server...")
    print("📍 Visit: http://127.0.0.1:5000")
    app.run(debug=True)