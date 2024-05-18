# create_roles.py
from app import Role, User, db

def create_roles():
    admin = Role(id=1, name='Admin')
    principal = Role(id=2, name='Principal')
    trad_notary = Role(id=3, name='Traditional Notary')
    e_notary = Role(id=4, name='Electronic Notary')

    db.session.add(admin)
    db.session.add(principal)
    db.session.add(trad_notary)
    db.session.add(e_notary)

    db.session.commit()
    print("Roles created successfully!")

create_roles()
