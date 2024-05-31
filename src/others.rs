use std::{collections::HashMap, path::Path};

use rusqlite::Connection;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use base64::{prelude::BASE64_STANDARD, Engine};


pub(crate) fn validate_json(val:&Value) -> Result<(),String>{
    let val = val.clone();
    let mut map:Vec<(&str,Option<&Value>)> = Vec::new() ;
    map.push(("root_path",      val.get("root_path")));
    map.push(("name",           val.get("name")));
    map.push(("crypted_keys",   val.get("crypted_keys")));
    map.push(("db_name",        val.get("db_name")));
    let mut errs = Vec::<String>::new();
    let mut err = false;
    for  (key,x) in map {
        match x {
            Some(_) => continue,
            None => {
                err = true;
                errs.push(format!("error on: {}\n",key));
            },
        }
    }
    //println!("\n\n------\nkeyler :{:?} \n\n------",val["keys"]);   
    if val.get("keys").unwrap() == &json!([]){
        err = true;
        errs.push("error on: no sql rows".to_string());
    }
    if err{
        return Err(format!("{:?}",errs));
    }else {
        return Ok(());
    }
}

pub(crate) fn encrpyt_database(conn:&Connection,pass:&Option<Vec<u16>>){
    let _ = match pass {
        Some(som) => {
            {
                let pass = hash_string::unhash_str(som);
                conn.execute(format!("pragma key = '{}';",pass).as_str(), [])
            }
        },
        None => return,
    };
    
}

pub fn new_table_template()->Value{
    json!(
        {
            "name":"users",
            "root_path":"./root/path/to/database/",
            "db_name":"database_name.db",
            "crypted_keys":["password"],
            "keys":[
//              {"key":"id","type":"INTEGER","constr":"PRIMARY KEY","auto":true,"name":"id"},
//              {"key":"user","type":"TEXT","constr":"unique","name":"isim"},
//              {"key":"password","type":"TEXT","constr":"not null","name":"şifre"},
            ]
        }
    )
}



pub fn get_typeof(tip:&str) -> Option<KeyTypes>{
    match tip {
        "INTEGER" | "İNTEGER" | "int" | "INT" | "İNT" => Some(KeyTypes::Int),
        "TEXT" | "Text" | "text" | "string" | "String" | "STRING" => Some(KeyTypes::Text),
        "REAL" | "Real" | "real" | "FLOAT" | "Float" | "float" => Some(KeyTypes::Real),
        "BLOB" | "blob" | "Blob" => Some(KeyTypes::Blob),
        "Null" | "None" | "NONE" | "NULL" => Some(KeyTypes::Null),
        _ => None
    }
}

#[derive(Debug,Serialize,Deserialize)]
pub struct SqlResult{
    pub(crate) key_names:HashMap<String,String>,
    pub(crate) values:Vec<HashMap<String,DataTypes>>
}

#[derive(Debug,Serialize,Deserialize)]
pub enum DataTypes{
    Text(String),
    Int(i32),
    Real(f32),
    Blob(Vec<u8>),
    Null
}
impl SqlResult{
    pub fn as_json(&self) -> serde_json::Value{
        let mut main = serde_json::Map::new();
        let key_names = serde_json::to_value(&self.key_names).unwrap();
        let mut values = Vec::new();
        for x in &self.values{
            let v = self.deserialize_value(x);
            values.push(v);
        }
        let values = serde_json::to_value(&values).unwrap();
        main.insert("key_names".to_string(), key_names);
        main.insert("values".to_string(), values);
        return json!(main);
    }
    pub fn as_generic<T>(&self) -> SqlGeneric<T>
    where T :  DeserializeOwned,{
        if self.values.len() == 0 {
            return SqlGeneric::Empty;
        }
        else if self.values.len()  == 1{
            let buf = self.deserialize_value(&self.values[0]);
            let res = serde_json::from_value::<T>(buf).unwrap();
            return SqlGeneric::One(res); 
        }
        else {
            let mut result = Vec::<T>::new();
            for x in &self.values{
                
                let buf = self.deserialize_value(x);
                //println!("{}",buf);
                let t = serde_json::from_value::<T>(buf).unwrap();
                result.push(t);
            }
            return SqlGeneric::Arr(result);
        }
    }

    fn deserialize_value(&self,val :&HashMap<String,DataTypes>) -> Value{
            let mut buf_map = serde_json::Map::new();
            for (key , val) in val{
                match val {
                    DataTypes::Text(valx) => buf_map.insert(key.clone(), json!(valx)),
                    DataTypes::Int(valx) => buf_map.insert(key.clone(), json!(valx)),
                    DataTypes::Real(valx) => buf_map.insert(key.clone(), json!(valx)),
                    DataTypes::Blob(valx) => {
                        buf_map.insert(key.clone(), json!(valx))
                    },
                    DataTypes::Null => buf_map.insert(key.clone(), json!(null)),
                };
            } 
            let buf = json!(buf_map);
            buf
    }
    


}

#[derive(Debug,PartialEq,Clone)]
pub enum KeyTypes{
    Int,
    Text,
    Real,
    Blob,
    Null
}
#[derive(Debug,Serialize)]
pub enum SqlGeneric<T>{
    One(T),
    Arr(Vec<T>),
    Empty,

    
}

impl<T> SqlGeneric<T> {
    pub fn is_arr(&self) -> bool{ 
        match &self {
        SqlGeneric::Arr(_) => true,
        _=> false
    }}
    pub fn is_one(&self) -> bool{ 
        match &self {
        SqlGeneric::One(_) => true,
        _=> false
    }}
    pub fn is_empty(&self) -> bool{ 
        match &self {
        SqlGeneric::Empty => true,
        _=> false
    }}
    pub fn arr(&self) -> &Vec<T>{
        match &self {
            SqlGeneric::Arr(a) => a,
            _=> panic!("Not arr")
        }
    }
    pub fn one(&self) -> &T{
        match &self {
            SqlGeneric::One(a) => a,
            _=> panic!("Not one")
        }
    }
    pub fn empty(&self) -> (){
        match &self {
            SqlGeneric::Empty => (),
            _=> panic!("zaa")
        }
    }
    pub fn arr_mut(&mut self) -> &mut Vec<T>{
        match self {
            SqlGeneric::Arr(a) => a,
            _=> panic!("Not arr")
        }
    }
    pub fn one_mut(&mut self) -> &mut T{
        match self {
            SqlGeneric::One(a) => a,
            _=> panic!("Not one")
        }
    }
    pub fn arr_real(self) -> Vec<T>{
        match self {
            SqlGeneric::Arr(a) => a,
            _=> panic!("Not arr")
        }
    }
    pub fn one_real(self) -> T{
        match self {
            SqlGeneric::One(a) => a,
            _=> panic!("Not one")
        }
    }
}


pub(crate) fn hahs_str(val:&str,cost:u32) -> String {
    let buf = bcrypt::hash(val, cost).unwrap();
    let e = BASE64_STANDARD.encode(buf);
    e
}

pub(crate) mod hash_string{
    use base64::prelude::*;
    pub fn hash_str(str:String) -> Vec<u16>{
        let str = BASE64_STANDARD.encode(str);
        let mut hashed = Vec::new();
        let mut count = 0;
        for x in str.as_bytes(){
            count += 1;
            hashed.push((x.clone() as u16 + count as u16));
        }
        drop(str);
        hashed
    
    }
    pub fn unhash_str(str:&Vec<u16>) -> String{
        let mut  count = 0;
        let mut unhashed = Vec::<u8>::new();
    
        for x in str{
            count +=1;
            unhashed.push((x - count) as u8);
        }
        let unhahed = String::from_utf8(unhashed).unwrap();
        let unhahed = BASE64_STANDARD.decode(unhahed).unwrap();
        let unhahed = String::from_utf8(unhahed).unwrap();
        unhahed
    
    }
}


pub(crate) struct UnionSearchthing{
    pub(crate) table:String,
    pub(crate) keys:Value
}
#[derive(Debug)]
pub(crate) struct UnionSearchQuery{
    pub(crate) path:String,
    pub(crate) query:String,
}

impl UnionSearchQuery {
    pub(crate) fn new(path: String, query: String) -> Self {
        Self { path, query }
    }
}

