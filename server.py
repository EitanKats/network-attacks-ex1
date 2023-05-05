from flask import Flask

# create a new Flask app
app = Flask(__name__)


# define a route for the root URL
@app.route('/')
def hello_world():
    return 'Hello, world!'


# start the server on port 8000
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
