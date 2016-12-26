from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session

#engine = create_engine('sqlite:///:memory:')
engine = create_engine('sqlite:///caca.db')

# Connect to the default database.
#engine = create_engine("postgresql+psycopg2://postgres:cafecafe@localhost:5432/postgres")
Session = scoped_session(sessionmaker(bind=engine))

 
