# create_roles.py
from app import Role, User, db

def create_roles():
    admin = Role(id=1, name='Admin')
    teacher = Role(id=2, name='Teacher')
    staff = Role(id=3, name='Staff')
    student = Role(id=4, name='Student')

    db.session.add(admin)
    db.session.add(teacher)
    db.session.add(staff)
    db.session.add(student)

    db.session.commit()
    print("Roles created successfully!")

# Function calling will create 4 roles as planned!
create_roles()
