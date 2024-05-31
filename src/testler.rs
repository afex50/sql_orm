use std::{cell::RefCell, collections::HashMap, path::Path, rc::Rc, sync::Arc};

use base64::prelude::*;
use bcrypt::BASE_64;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::json;
use crate::{new_table, orm};
#[macro_use]
use crate::prelude::{SqlGeneric, SqlOrm,};

macro_rules! test_orm {
    () => {
        {
            SqlOrm::init(Some("ahmte.efe".to_string()), "./sql_test.json".to_string(), 4)
            
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
    let orm = SqlOrm::init(Some("ahmte.efe".to_string()), "./sql_test.json".to_string(), 4);
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
    let mut orm = SqlOrm::init(Some("ahmte.efe".to_string()), "./sql_test.json".to_string(), 4);
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
    let orm = SqlOrm::init(Some("ahmte.efe".to_string()), "./sql_test.json".to_string(), 4);
    let e = orm.search("users".to_string(), 1).unwrap();
    println!("{:#?}",e.as_json());  
}

#[derive(Deserialize, Serialize, Debug)]
struct User {
    id: i32,
    user: String,
    password: String,
    pic:Vec<u8>
}

#[test]
fn test_generic() {
    let orm = SqlOrm::init(Some("ahmte.efe".to_string()), "./sql_test.json".to_string(), 4);
    let e = orm.search("users".to_string(), 3).unwrap();
    let person = e.as_generic::<User>();
    match person {
        SqlGeneric::One(usr) => println!("{:?}", usr),
        SqlGeneric::Arr(usrs) => println!("{:#?}", usrs),
        SqlGeneric::Empty => (),
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
    pic:Vec<u8>
}

#[test]
fn test_insert_generic() {
    let orm = SqlOrm::init(Some("ahmte.efe"), "./sql_test.json", 4);
    let user = UserG {
        user: "efefefe".to_string(),
        password: "asfewpıfema".to_string(),
        pic:vec![1,23,4,42,13,233,231]
    };
    let mut vec = Vec::new();
    let e = orm.insert_generic("users", SqlGeneric::One(user));
    vec.push(e);
    let user1 = UserG {
        user: "salamo od".to_string(),
        password: "dslfmaspkas".to_string(),
        pic:vec![1,23,4,42,255,12,244]
    };
    let user2 = UserG {
        user: "alakug".to_string(),
        password: "gğprwogw".to_string(),
        pic:vec![1,23,4,42,255,255,255]
    };
    let generics = vec![user1, user2];
    let e = orm.insert_generic("users", SqlGeneric::Arr(generics));
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

#[test]
fn test_drop_table(){
    let mut orm = test_orm!();
    orm.remove_table("users").unwrap();
}

#[test]
fn test_insert_blob(){}

#[test]
fn test_blob_insert_to_db(){
    let conn = Connection::open_in_memory().unwrap();
    conn.execute("CREATE TABLE IF NOT EXISTS blob (b BLOB)", params![]).unwrap();

    let file = std::fs::read("./admin.jpg").unwrap();
    let bfile = BASE64_STANDARD.encode(file);
    let sql = format!("INSERT INTO blob (b) values ('{}')",bfile);
    conn.execute(&sql, params![]).unwrap();



    let vec = vec![1,42,5,3,23,52,5];
    let vec = String::from_utf8(vec).unwrap();
    let sql = format!("INSERT INTO blob (b) values ('{}')",vec);
    conn.execute(&sql, params![]).unwrap();
    let mut stmt = conn.prepare("select * from blob").unwrap();
    let mut names = Vec::<String>::new();
    let mut rows = stmt.query([]).unwrap();
    while let Some(row) = rows.next().unwrap() {
        names.push(row.get(0).unwrap());
    }
    println!("{:#?}",names);
    std::fs::write("./out.base64", names[0].clone());
    let file2 = BASE64_STANDARD.decode(names[0].clone()).unwrap();
    std::fs::write("./out.jpg", file2).unwrap();
    
}




#[test]
fn arc_test(){
  let mut e = Arc::new(RefCell::new(232));
  e.replace(2);
  let mut af = e.clone();
  af.replace(42);
  println!("{:?}",e);
}


#[test]
fn test_inner_join(){
    let conn = Connection::open_in_memory().unwrap();
    conn.execute("CREATE TABLE IF NOT EXISTS table_a (b TEXT, a TEXT,c INT)", params![]).unwrap();
    conn.execute("CREATE TABLE IF NOT EXISTS table_b (b TEXT, a_a TEXT,c INT)", params![]).unwrap();
    conn.execute(r#"INSERT INTO table_a (b,a,c) Values('efe','ahmet',1)"#, params![])     .unwrap();
    conn.execute(r#"INSERT INTO table_a (b,a,c) Values('tuna','furkan',2)"#, params![])   .unwrap();
    conn.execute(r#"INSERT INTO table_a (b,a,c) Values('efe','furkan',3)"#, params![])    .unwrap();
    conn.execute(r#"INSERT INTO table_a (b,a,c) Values('furkan','ahmet',4)"#, params![])  .unwrap();
    conn.execute(r#"INSERT INTO table_b (b,a_a,c) Values('zaza','baba',11)"#, params![])  .unwrap();
    conn.execute(r#"INSERT INTO table_b (b,a_a,c) Values('zuzu','bobo',12)"#, params![])  .unwrap();
    conn.execute(r#"INSERT INTO table_b (b,a_a,c) Values('zozo','bebe',13)"#, params![])  .unwrap();
    conn.execute(r#"INSERT INTO table_b (b,a_a,c) Values('zeze','bıbı',14)"#, params![])  .unwrap();


    let mut objects = Vec::<serde_json::Value>::new();
    let mut stmt = conn.prepare("select distinct b,c from table_a union select b,c from table_b").unwrap();

    let mut rows = stmt.query([]).map_err(|err| {return format!("{:?}",err);}).unwrap();
    while let Some(row) = rows.next().unwrap() { 
        println!("{:?}",&row);
        objects.push(json!( {   
            //"b": row.get::<usize,Option<String>>(0).unwrap(),
            //"c": row.get::<usize,Option<i32>>(1).unwrap(),
            //"c": row.get::<usize,i32>(2).unwrap(),
        }));

    }



    //println!("{:#?}",objects);


}


#[test]
fn test_val_eq(){
    let a = json!({
        "sa":"as",
        "la":"ula"
    });
    let b = json!({
        "sa":"as",
        "la":"ulan"
    });
    assert_eq!(a,b)
}

#[test]
fn test_union_search(){
    let orm = SqlOrm::init(None, "./sql_test.json", 5);
    /*{
        orm.insert("users", json!({"user":"ahmet1","password":"solo","pic":"htrsjyrjty"})).unwrap();
        orm.insert("efe", json!({"user":"efe","password":"sala","desc":"asfasfafs"})).unwrap();
        orm.insert("efe", json!({"user":"efe1","password":"sala","desc":"tjrydyhrhf"})).unwrap();
        orm.insert("efe", json!({"user":"efe2","password":"sala","desc":"asdasfdfa"})).unwrap();
        orm.insert("efe", json!({"user":"efe3","password":"sala","desc":"djswrgaerg"})).unwrap();
        orm.insert("efe", json!({"user":"efe4","password":"sala","desc":"bjcdrjtsrh"})).unwrap();
        orm.insert("efe", json!({"user":"efe5","password":"sala","desc":"aşsmfasfkmep"})).unwrap();
        orm.insert("efe", json!({"user":"efe6","password":"sala","desc":"htrsjyrjty"})).unwrap();
        orm.insert("users", json!({"user":"ahmet","password":"solo","pic":"htrsjyrjty"})).unwrap();
        orm.insert("users", json!({"user":"ahmet2","password":"solo","pic":"htrsjyrjty"})).unwrap();
        orm.insert("users", json!({"user":"ahmet3","password":"solo","pic":"htrsjyrjty"})).unwrap();
        orm.insert("users", json!({"user":"ahmet4","password":"solo","pic":"htrsjyrjty"})).unwrap();
        orm.insert("users", json!({"user":"ahmet5","password":"solo","pic":"htrsjyrjty"})).unwrap();
    }
    */


    orm.union_search(vec!["efe".to_string(),"users".to_string()], 10);
}


#[test]
fn anc_test(){
    let path = Path::new("./sa/as/naber.js");
    let mut anc = path.ancestors();
    let a = path.parent().unwrap();
    let a :Vec<u8>= path.file_name().unwrap().to_str().unwrap().bytes().collect();
    let str = String::from_utf8(a).unwrap();
    println!("{:?}",str);
    println!("{}",anc.next().unwrap().to_str().unwrap());
    println!("{:?}",anc.next());
    println!("{:?}",anc.next());

}