from flask import Flask, request
app = Flask(__name__)

@app.route('/login',methods=['POST'])
def login():
    print("Received POST data:", request.data.decode())
    return "OK", 200

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    return "Static response", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
