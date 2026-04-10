from app import create_app
from app.config import Config

app = create_app('development')

if __name__ == '__main__':
    try:
        from waitress import serve
        serve(app, host=Config.HOST, port=Config.PORT)
    except Exception:
        app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)
