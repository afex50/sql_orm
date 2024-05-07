use std::collections::HashMap;

use base64::prelude::*;
use bcrypt::BASE_64;
use serde::{Deserialize, Serialize};
use serde_json::json;
use crate::{new_table, orm};
#[macro_use]
use crate::orm::{SqlGeneric, SqlOrm,};

macro_rules! test_orm {
    () => {
        {
            let mut orm = SqlOrm::init(Some("ahmte.efe".to_string()), &"./sql_test.json".to_string(), 4);
            let table = new_table!();
            orm.new_table(table).unwrap();
            orm
        }
    };
}

#[test]
fn deneme() {
    assert!(true)
}

#[test]
fn test_hashmap() {
    let mut e = HashMap::<&str, &str>::new();
    let f = json!({"keys":[]});
    let ef = f.get("keys");
    println!("{:?}", ef.unwrap().as_array().unwrap());

    e.insert("sa", "efe").insert("fe");
    e.insert("as", "dfase");
    println!("{:?}", e);
}

#[test]
fn test_json() {
    let e = json!(
        {
            "name":"users",
            "root_path":"./db/users/",
            "db_name":"main.db",
            "crypted":true,
            "crypted_keys":["password"],
            "keys":[
                {"key":"id","type":"INTEGER","constr":"AUTO INCREMENT","auto":true},
                {"key":"user","tpye":"text","constr":"unique","name":"isim"},
                {"key":"password","type":"text","constr":"not null","name":"şifre"},
            ]
        }
    );
    let f = e["keys"].as_array().unwrap();
    let mut keys = Vec::<String>::new();
    for x in f {
        //let y = x.as_object().unwrap();
        let a = format!("{} {:?}", x["key"], x["value"]);
        keys.push(a);
        keys.push(",".to_string());
    }
    keys.pop();
    println!("{}", format!("{}", keys.into_iter().collect::<String>()))
}

#[test]
fn test_orm_search() {
    let orm = SqlOrm::init(Some("ahmte.efe".to_string()), &"./sql_test.json".to_string(), 4);
    let e = orm.search("users".to_string(), 2);
    println!("{:?}",e.unwrap().as_generic::<User>().arr())
}

#[test]
fn test_orm_insert() {
    let x : Box<dyn Fn()>;
    let e = json!(
        {
            "name":"users",
            "root_path":"./db/users/",
            "db_name":"main.db",
            "crypted":true,
            "crypted_keys":["password"],
            "keys":[
                {"key":"id","type":"INTEGER","constr":"PRIMARY KEY","auto":true,"name":"id"},
                {"key":"user","type":"TEXT","constr":"unique","name":"isim"},
                {"key":"password","type":"TEXT","constr":"not null","name":"şifre"},
            ]
        }
    );
    //let mut orm = SqlOrm::init("vD01Cm8M&2K4hQ6VjeoqH", Some("ahmte.efe".to_string()), "./sql_test.json");
    let mut orm = SqlOrm::init(Some("ahmte.efe".to_string()), &"./sql_test.json".to_string(), 4);
    orm.new_table(e.clone()).unwrap();
    let mut v = Vec::<Result<(), String>>::new();
    let a = orm.insert(
        "users".to_string(),
        json!({"user":"efe","password":"6513dfsghes"}),
    );
    v.push(a);
    let a = orm.insert(
        "users".to_string(),
        json!([{"user":"gurusu ","password":"12341234"},{"user":"murdis","password":"98769876"}]),
    );
    v.push(a);
    for x in v {
        match x {
            Ok(ok) => println!("ok"),
            Err(err) => eprintln!("err: {}", err),
        }
    }
}

#[test]
fn test_search() {
    let orm = SqlOrm::init(Some("ahmte.efe".to_string()), &"./sql_test.json".to_string(), 4);
    let e = orm.search("users".to_string(), 1).unwrap();
    println!("{:#?}",e.as_json());  
}

#[derive(Deserialize, Serialize, Debug)]
struct User {
    id: i32,
    user: String,
    password: String,
}

#[test]
fn test_generic() {
    let orm = SqlOrm::init(Some("ahmte.efe".to_string()), &"./sql_test.json".to_string(), 4);
    let e = orm.search("users".to_string(), 3).unwrap();
    let person = e.as_generic::<User>();
    match person {
        SqlGeneric::One(usr) => println!("{:?}", usr),
        SqlGeneric::Arr(usrs) => println!("{:#?}", usrs),
        SqlGeneric::Empty => println!("boş"),
    }
    let e = orm.search("users".to_string(), 1).unwrap();
    let person = e.as_generic::<User>();
    println!("{:?}",person)
}

#[cfg(test)]
mod hashs{
    use base64::prelude::*;
    #[test]
    fn hash_password() {
        let pass = "MERHABAsafasfpasnfaslkfnaw".to_string();
        let hashed = { hash_str(pass.clone()) };
        println!("{:?}", hashed);

        let unhashed = unhash_str(&hashed);
        println!("{unhashed}");
        assert_eq!(pass, unhashed);
    }
    fn hash_str(str: String) -> Vec<u16> {
        let str = BASE64_STANDARD.encode(str);
        let mut hashed = Vec::new();
        let mut count = 0;
        for x in str.as_bytes() {
            count += 1;
            hashed.push((x.clone() as u16 + count as u16));
        }
        drop(str);
        hashed
    }
    fn unhash_str(str: &Vec<u16>) -> String {
        let mut count = 0;
        let mut unhashed = Vec::<u8>::new();

        for x in str {
            count += 1;
            unhashed.push((x - count) as u8);
        }
        let unhahed = String::from_utf8(unhashed).unwrap();
        let unhahed = BASE64_STANDARD.decode(unhahed).unwrap();
        let unhahed = String::from_utf8(unhahed).unwrap();
        unhahed
    }
}


#[derive(Debug, Deserialize, Serialize)]
struct UserG {
    user: String,
    password: String,
}

#[test]
fn test_insert_generic() {
    let orm = SqlOrm::init(Some("ahmte.efe".to_string()), &"./sql_test.json".to_string(), 4);
    let user = UserG {
        user: "efefefe".to_string(),
        password: "asfewpıfema".to_string(),
    };
    let mut vec = Vec::new();
    let e = orm.insert_generic("users".to_string(), SqlGeneric::One(user));
    vec.push(e);
    let user1 = UserG {
        user: "salamo od".to_string(),
        password: "dslfmaspkas".to_string(),
    };
    let user2 = UserG {
        user: "alakug".to_string(),
        password: "gğprwogw".to_string(),
    };
    let generics = vec![user1, user2];
    let e = orm.insert_generic("users".to_string(), SqlGeneric::Arr(generics));
    vec.push(e);
    for x in vec {
        match x {
            Ok(ok) => println!("ok"),
            Err(err) => eprintln!("err: {}", err),
        }
    }
}

#[test]
fn test_macro(){
    let table = new_table!();
    for x in table.as_object().unwrap(){
        println!("{:?}",x)
    }
    if {
        let a = 21;
        a == 21
    }{

    }
}

#[derive(Debug, Deserialize, Serialize)]
struct UserGet{
    user:String
}
#[test]
fn test_search_field(){
    let mut orm = test_orm!();
    let data = orm.search_w_n("users".to_string(), 4, vec!["user".to_string()]).unwrap();
    let user = data.as_generic::<UserGet>();
    println!("{:#?}",user);
    
}

