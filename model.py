import datetime
from peewee import *

db = SqliteDatabase('db.db')

class Post(Model):
    name = CharField()
    role = CharField()
    post_count = IntegerField()
    message = TextField()
    avatar_id = IntegerField()
    created = DateTimeField(default=datetime.datetime.now)

    class Meta:
        database = db

def init_database():
    try:
        db.create_tables([Post])
    except Exception as e:
        raise e