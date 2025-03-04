#from app import app, db, User, Server

#with app.app_context():
    # Check tables
#    print(db.engine.table_names())

    # Check if tables exist
#    print(User.__table__)
#    print(Server.__table__)


#from app import app, db

#with app.app_context():
    # Drop all tables if they exist
    db.drop_all()
    
    # Create all tables
    db.create_all()

    print("Database and tables created!")


from app import app, db

with app.app_context():
    print("Tables:", db.engine.table_names())