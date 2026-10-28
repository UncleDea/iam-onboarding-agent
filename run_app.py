"""Run the IAM web app:  python run_app.py

Configuration comes from the environment (see iam_agent/config.py).
By default it binds 127.0.0.1:8000 with the SQLite provider.
"""

from iam_agent.webapp import main

if __name__ == "__main__":
    main()
