#!/usr/bin/python

from __future__ import print_function

import mysql.connector
from mysql.connector import errorcode
import argparse

DB_NAME = 'dnstool'

TABLES = {}
TABLES['queries'] = (
    "CREATE TABLE `queries` ("
    "  `qid` int(11) NOT NULL AUTO_INCREMENT,"
    "  `exp_id` varchar(10) NOT NULL,"
    "  `src_ip` varchar(15) NOT NULL,"
    "  `src_port` int NOT NULL,"
    "  `query` varchar(255) NOT NULL,"
    "  `trans_id` int NOT NULL,"
    "  `ip_id` int NOT NULL,"
    "  `open` tinyint NOT NULL,"
    "  `time` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
    "  PRIMARY KEY (`qid`)"
    ") ENGINE=InnoDB")
    
TABLES['fdns'] = (
    "CREATE TABLE `fdns` ("
    "  `fid` int(11) NOT NULL AUTO_INCREMENT,"
    "  `exp_id` varchar(10) NOT NULL,"
    "  `src_ip` varchar(15) NOT NULL,"
    "  `open` tinyint NOT NULL,"
    "  `preplay` tinyint NOT NULL,"
    "  `time` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
    "  PRIMARY KEY (`fid`)"
    ") ENGINE=InnoDB")
    
def create_database(cursor):
    try:
        cursor.execute(
            "CREATE DATABASE {} DEFAULT CHARACTER SET 'utf8'".format(DB_NAME))
    except mysql.connector.Error as err:
        print("Failed creating database: {}".format(err))
        exit(1)
    
if __name__ == "__main__":
    # set up command line args
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                                     description='Create the dnstool database')
    parser.add_argument('-u', '--username', default='root')
    parser.add_argument('-p', '--password', default=None)
    args = parser.parse_args()
    
    cnx = mysql.connector.connect(user=args.username, password=args.password)
    cursor = cnx.cursor()
    
    try:
        cnx.database = DB_NAME    
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_BAD_DB_ERROR:
            create_database(cursor)
            cnx.database = DB_NAME
        else:
            print(err)
            exit(1)
            
    for name, ddl in TABLES.iteritems():
        try:
            print("Creating table {}: ".format(name), end='')
            cursor.execute(ddl)
        except mysql.connector.Error as err:
            if err.errno == errorcode.ER_TABLE_EXISTS_ERROR:
                print("already exists.")
            else:
                print(err.msg)
        else:
            print("OK")

    cursor.close()
    cnx.close()
