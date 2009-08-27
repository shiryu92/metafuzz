#!/usr/bin/env python
#
# (c) 2009, the grugq <the.grugq@gmail.com>

from contextlib import contextmanager
from sqlalchemy import (Column, String, Integer, ForeignKey)
from sqlalchemy.ext.declarative import declarative_base

import os
import sqlite3

DB_PATH="C:\\runtracer\\modules.sqlite"

# SCHEMA
def create_db(path="C:\\runtracer\\modules.sqlite"):
    module_table = """CREATE TABLE modules IF NOT EXISTS (
    id  INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    md5  TEXT NOT NULL
    );"""
    function_table = """CREATE TABLE functions IF NOT EXISTS (
    id  INTEGER PRIMARY KEY,
    address INTEGER NOT NULL,
    name    TEXT NOT NULL,
    module_id  INTEGER REFERENCES modules (id),
    )"""

Base = declarative_base()

class Module(Base):
    __tablename__ = "modules"

    id  = Column(Integer, primary_key=True)
    name    = Column(String, nullable=False)
    path    = Column(String, nullable=False)
    md5sum  = Column(String, nullable=False)

    def __init__(self, name, path, md5sum):
        self.name = name
        self.path = path
        self.md5sum = md5sum
    def __repr__(self):
        return "<Module(%s) %s [%s]>" % (self.name, self.path, self.md5sum)

class Function(Base):
    __tablename__ = "functions"

    id  = Column(Integer, primary_key=True)
    address = Column(Integer, nullable=False)
    name    = Column(String, nullable=False)
    module_id=Column(Integer, ForeignKey("modules.id"))

    module  = reference(Module, backref=backref('functions', order_by=id))

    def __init__(self, address, name, module):
        self.address = address
        self.name = name
        self.module = module

    def __repr__(self):
        return "<Function %08x %s::%s>" % (self.address, self.module.name,
                                           self.name)

class ModuleList(object):
    def __init__(self, db):
        self.db = db
    def query(self, **kwargs):
        return self.db.session.query(Module).filter_by(**kwargs)
    def by_path(self, path):
        return self.query(path=path)
    def by_name(self, name):
        return self.query(name=name)
    def by_md5sum(self, md5sum):
        return self.query(md5sum=md5sum)
    def __getitem__(self, name):
        return self.from_name(name)
    def __iter__(self):
        return self.db.session.query(Module).all()
    def keys(self):
        return self.db.session.query(Module.name).all()

class TracerDB(object):
    def __init__(self, uri):
        self.engine = create_engine(uri)
        self.session = Session()
        Base.metadata.create_all(self.engine)

        self.modules = ModuleList(self)
