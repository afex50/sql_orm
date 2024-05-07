use std::{collections::HashMap, fmt::format, path::{self, Path}};

use rusqlite::{params, Connection};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use base64::prelude::*;

#[macro_export]
macro_rules! new_table {
    () => {
        {
            json!(
                {
                    "name":"users",
                    "root_path":"./root/path/to/database/",
                    "db_name":"database_name.db",
                    "crypted":true,
                    "crypted_keys":["password"],
                    "keys":[
                        {"key":"id","type":"INTEGER","constr":"PRIMARY KEY","auto":true,"name":"id"},
                        {"key":"user","type":"TEXT","constr":"unique","name":"isim"},
                        {"key":"password","type":"TEXT","constr":"not null","name":"şifre"},
                    ]
                }
            )
        }
    };
}

/// salt:bcrypt için şifre, pass:veritabanı şifresi
/// 
/// 
#[derive(Debug)]
pub struct SqlOrm{
    password:Option<Vec<u16>>,
    metadata_path:String,
    tables:HashMap<String,(TableMeta,SqlTable)>,
    bcrypt_cost:u32
}



#[derive(Eq, Hash, PartialEq,Debug,Clone)]
struct TableMeta{
    name:String,
    root_path:String,
    db_name:String,
    crypted_keys:Option<Vec<String>>
}
///  keys stored in here
/// ```
/// [{"key":"id","value":"INTEGER AUTO INCREMENT","auto":true},...]
/// ```
#[derive(Debug)]
pub struct SqlTable{
    data:Value
}


pub enum SqlErr{
    DbNotFound(String),
}

#[derive(Debug,Clone)]
enum Lul {
    Json(Value),
    Data(TableMeta)
}


/// SqlResult {
/// 
///     key_names:("id":"id","name":"kullanıcı adı"),
/// 
///     values: [
/// 
///         ("id":Int(1)),
/// 
///         ("name":Text("admin")),
/// 
///         ("pass":Blob([1,5,3,6]))
/// 
///     ], ...
/// 
/// }
/// 

impl SqlOrm {
    ///vay amk  
    /// bu bi yorum
    pub fn init(pass:Option<String>,meta_path:&String,bcrypt_cost:u32) -> Self{
        let val:Value;
        if std::path::Path::new(meta_path).exists(){
            let reader = std::fs::read(std::path::Path::new(meta_path)).unwrap();
            val = match serde_json::from_str(&String::from_utf8(reader).unwrap()) {
                Ok(ok) => ok,
                Err(_) => json!([]),
            };
        }else {
            let mut anc = std::path::Path::new(meta_path).ancestors();
            anc.next();
            let _ = 
            (
                std::fs::create_dir_all(anc.next().unwrap()).map_err(|_err|  {panic!("{:?}",_err)}),
                std::fs::write(meta_path, json!([]).to_string()).map_err(|_err|  {panic!("{:?}",_err)})
            );
            val = json!([]);
        }
        let mut tables = HashMap::<String,(TableMeta,SqlTable)>::new();
        let mut counter = 1;

        let mut row_count = 1;
        for row in val.as_array().unwrap(){
            match validate_json(row){
                Ok(_) => (),
                Err(err) => {eprintln!("error on reading table {} -> {} ",counter,err);continue;},
            };
            let crypt_keys = match row.get("crypted_keys") {
                Some(ok) => {
                    let mut ret = Vec::new();
                    for x in ok.as_array().unwrap(){
                        ret.push(x.as_str().unwrap().to_string());
                    }
                    Some(ret)
                },
                None => None,
            };
            let meta_buf = TableMeta{

                crypted_keys:crypt_keys,
                db_name:        row.get("db_name").unwrap().as_str().unwrap().to_string(),
                name:           row.get("name").unwrap().as_str().unwrap().to_string(),
                root_path:      row.get("root_path").unwrap().as_str().unwrap().to_string()
            };
            row_count += 1;
            
            let buf = SqlTable{data:row.get("keys").unwrap().clone()};
            tables.insert( row.get("name").unwrap().as_str().unwrap().to_string(),(meta_buf,buf) );
            counter += 1;
        }
        let pass = {
            match pass {
                Some(som) => Some(hash_str::hash_str(som)),
                None => None,
            }
        };

        return Self{
            metadata_path:meta_path.to_string(),
            password:pass,
            tables:tables,
            bcrypt_cost:bcrypt_cost
        };
    }
    pub fn new_table(
        &mut self,
        val:Value
    ) -> Result<(),String>{
        
        match validate_json(&val){
            Ok(_) => (),
            Err(err) => return Err(err),
        };
        let buf = SqlTable{
            data:val["keys"].clone()
        };
        let crypt_keys = match val.get("crypted_keys") {
            Some(ok) => {
                let mut ret = Vec::new();
                for x in ok.as_array().unwrap(){
                    ret.push(x.as_str().unwrap().to_string());
                }
                Some(ret)
            },
            None => None,
        };
        let name = val.get("name").unwrap().as_str().unwrap().to_string();
        let db_path = format!("{}/{}",val["root_path"],val["db_name"]);

        let conn = match self.connect_db(&Lul::Json(val.clone())){
            Ok(ok) => ok,
            Err(err) => return Err(err),
        };
        encrpyt_database(&conn, &self.password);
        
        let keys:String = {
            let f = val["keys"].as_array().unwrap();
            let mut keys = Vec::<String>::new();
            for x in f {
                let a = format!("{} {} {}",x["key"],x["type"].as_str().unwrap(),x["constr"].as_str().unwrap());
                keys.push(a);
                keys.push(",".to_string());
            }
            keys.pop();
            keys.into_iter().collect::<String>()
        };
        let sql = format!("CREATE TABLE IF NOT EXISTS {} ({})",name.as_str(),keys.as_str());
        //println!("{}",sql); 
        match conn.execute(&sql, []){
            Ok(_) => (),
            Err(err) => return Err(format!("bişeyler yanlış gitti {}",err)),
        };
        
        
        let meta_buf = TableMeta{
            crypted_keys:crypt_keys,
            db_name:     val.get("db_name").unwrap().as_str().unwrap().to_string(),
            name:        name.clone(),
            root_path:   val.get("root_path").unwrap().as_str().unwrap().to_string()
        };
        //println!("{}\n----\n{:?}\n----\n{:?}",meta_buf.db_name,buf,val.get("db_name").unwrap().as_str().unwrap().chars().as_str());
        self.tables.insert(name ,(meta_buf, buf));
        self.save_metadata();
        Ok(())
    }

    /// drops the table
    pub fn remove_table(&mut self,table_name:String) -> Result<(), String>{
        let (meta,tables) = self.tables.get(&table_name).unwrap();
        let conn = match self.connect_db(&Lul::Data(meta.to_owned())){
            Ok(ok) => ok,
            Err(err) => return Err(err),
        };
        encrpyt_database(&conn, &self.password);
        let sql_ = format!("DROP TABLE {}",table_name);
        match conn.execute(&sql_, params![]){
            Ok(_ok) => {
                self.tables.remove(&table_name);
                return Ok(());
            },
            Err(err) => {
                return Err(format!("error dropping table from sql {}",err));
            },
        };
    }



    pub fn insert_generic<T>(&self,table:String,generic:SqlGeneric<T>) -> Result<(),String> where T : Serialize{

        let val :Value;
        match generic {
            SqlGeneric::One(som) => {
                val = serde_json::to_value(som).unwrap();
            },
            SqlGeneric::Arr(som) => {
                //println!("{:?}",serde_json::to_value(&som).unwrap());
                val = serde_json::to_value(som).unwrap();
            },
            SqlGeneric::Empty => return Err("Boş".to_string()),
        };
        return self.insert(table, val);
    }

    /// # Example
    /// ```
    /// insert("Users",serde_json::json!({"user":"salam","password":"12341234"}))
    /// ```
    pub fn insert(&self,table:String,val:Value) -> Result<(),String>{
        let (meta,tables) = self.tables.get(&table).unwrap();
        let conn = match self.connect_db(&Lul::Data(meta.to_owned())){
            Ok(ok) => ok,
            Err(err) => return Err(err),
        };
        encrpyt_database(&conn, &self.password);

        let mut keys = Vec::<(&str,KeyTypes)>::new();
        for x in tables.data.as_array().unwrap(){
            //keys
            let key: &str;
            if x.get("auto") == None || x.get("auto") == Some(&json!(false)){
                key = x.get("key").unwrap().as_str().unwrap();
            }
            else {
                continue;
            }
            //key_types
            let ktype = x["type"].as_str().unwrap();
            keys.push((key,get_typeof(ktype).unwrap()));

        }
        //println!("{:?}",keys);


        if val.is_array(){
            if val.get(0) == None{
                return Err("boş liste".to_string());
            }
            let mut errs = Vec::<String>::new();
            let mut error = false;
            for x in val.as_array().unwrap(){
                let map = x.as_object().unwrap();
                let mut values = Vec::<String>::new();
                let mut key_names = Vec::<String>::new(); 
                for (key,valu) in map {
                    let mut valx = valu.as_str().unwrap().to_string();
                    for x in &meta.crypted_keys{
                        if x.contains(key){
                            let e = hahs_str(valu.as_str().unwrap(),self.bcrypt_cost).to_string();
                            valx = e.clone();
                        }
                    }
                    if keys.contains(&(key.as_str(),KeyTypes::Text)){
                        key_names.push(key.to_string());
                        key_names.push(",".to_string());
                        values.push("'".to_string());
                        values.push(valx);
                        values.push("'".to_string());
                        values.push(",".to_string());
                    }else if keys.contains(&(key.as_str(),KeyTypes::Int)) || keys.contains(&(key.as_str(),KeyTypes::Real)) {
                        key_names.push(key.to_string());
                        key_names.push(",".to_string());
                        values.push(valx);
                        values.push(",".to_string());

                    }
                    else {
                        return Err("error in sql query".to_string());
                    }
                    
                }
                values.pop();
                key_names.pop();

                let value_names = values.into_iter().collect::<String>();
                let key_name = key_names.clone().into_iter().collect::<String>();
                let query = format!("INSERT INTO {} ({}) Values({})",meta.name,key_name,value_names);
                
                //insert
                match conn.execute(&query, params![]){
                    Ok(_ok) => (),
                    Err(err) => {
                        error = true;
                        errs.push(format!("{}",err));
                        errs.push(", ".to_string());
                    },
                };
            }
            errs.pop();
            if error{
                return Err(errs.concat());
            }else {
                return Ok(());
            }            
        }
        //if not an array
        else {
            let x = val.clone();
            let mut errs = Vec::<String>::new();
            let mut error = false;


            let map = x.as_object().unwrap();
            let mut values = Vec::<String>::new();
            let mut key_names = Vec::<String>::new(); 
            for (key,valu) in map {
                let mut valx = valu.as_str().unwrap().to_string();
                for x in &meta.crypted_keys{
                    if x.contains(key){
                        let e = hahs_str(valu.as_str().unwrap(),self.bcrypt_cost).to_string();
                        valx = e.clone();
                    }
                }
                //println!("{}",&valx);
                if keys.contains(&(key.as_str(),KeyTypes::Text)){
                    key_names.push(key.to_string());
                    key_names.push(",".to_string());
                    values.push("'".to_string());
                    values.push(valx);
                    values.push("'".to_string());
                    values.push(",".to_string());
                }else if keys.contains(&(key.as_str(),KeyTypes::Int)) || keys.contains(&(key.as_str(),KeyTypes::Real)) {
                    key_names.push(key.to_string());
                    key_names.push(",".to_string());
                    values.push(valx);
                    values.push(",".to_string());

                }
                else {
                    return Err("error in sql query".to_string());
                }
                
            }
            values.pop();
            key_names.pop();

            let value_names = values.into_iter().collect::<String>();
            let key_name = key_names.clone().into_iter().collect::<String>();
            let query = format!("INSERT INTO {} ({}) Values({})",meta.name,key_name,value_names);
            
            //insert
            match conn.execute(&query, params![]){
                Ok(_ok) => (),
                Err(err) => {
                    error = true;
                    errs.push(format!("{}",err));
                    errs.push(", ".to_string());
                },
            };


            errs.pop();
            if error{
                return Err(errs.concat());
            }else {
                return Ok(());
            }            
        }
    }
    fn search_inner(&self,sql_query:String,table:String,search_names:Option<Vec<String>>) ->Result<SqlResult,String> {
        let (meta,STable) = self.tables.get(&table).unwrap();
        let conn:Connection = match self.connect_db(&Lul::Data(meta.clone())){
            Ok(ok) => ok,
            Err(err) => return Err(err),
        };
        
        let mut keynames = HashMap::<String,String>::new();
        let mut keyname_types = Vec::<(String,KeyTypes)>::new();
        for val in STable.data.as_array().unwrap(){
            // println!("values : {:?}\n",val);
            match val.get("name") {/////{/////{/////{/////{/////{/////{/////
                Some(som) => {
                    match get_typeof(&val.get("type").unwrap().as_str().unwrap().to_string()) {
                        Some(somkey) => keyname_types.push((val.get("key").unwrap().as_str().unwrap().to_string(), somkey)),
                        None => return Err("error on metadata".to_string()),
                    };
                    keynames.insert(som.as_str().unwrap().to_string(), val.get("key").unwrap().as_str().unwrap().to_string())
                },
            None => continue,
            };
        }
        // println!("keynames :{:?}\nkeynametypes: {:?}",keynames,keyname_types);
        
        
        
        let mut result = SqlResult{key_names:keynames,values:Vec::new()};

        encrpyt_database(&conn, &self.password);

        println!("{}",sql_query);
        let query = sql_query;
        let mut stmt = conn.prepare(&query).unwrap();
        let mut rows = stmt.query([]).unwrap();


    
        match &search_names {
            Some(som) => {
                let mut old = keyname_types.clone();
                keyname_types = Vec::new();
                for x in som {
                    let mut ok = false;
                    for (k,t) in &old {
                        println!("x: {}, k: {}",x,k);
                        if x == k {
                            keyname_types.push((k.to_string(),t.clone()));
                            ok = true;
                        }
                    }
                    if !ok {
                        return Err("Aranan sütun bulunamadı".to_string());
                    }

                }
            },
            None => (),
        }

        while let Some(row) = rows.next().unwrap() {
            let mut counter = 0;
            let mut datas = HashMap::<String,DataTypes>::new();
            for (key,ktype) in &keyname_types{
                
                // println!("{counter}");
                
                let rowdata = match ktype {
                    KeyTypes::Int =>  DataTypes::Int(row.get(counter).unwrap()),
                    KeyTypes::Text => DataTypes::Text(row.get(counter).unwrap()),
                    KeyTypes::Real => DataTypes::Real(row.get(counter).unwrap()),
                    KeyTypes::Blob => DataTypes::Blob(row.get(counter).unwrap()),
                    KeyTypes::Null => DataTypes::Null,
                };
                println!("{:?}",rowdata);
                datas.insert(key.clone(), rowdata);
                counter += 1;
            }
            result.values.push(datas);
        }
        
        Ok(result)
    }
    pub fn search(&self,table:String,count:u32) -> Result<SqlResult,String>{    
        let sql_query = format!("SELECT * FROM {} LIMIT {}",table,count);
        self.search_inner(sql_query, table,None)
    }
    //blob and bull unsupported
    pub fn search_where(&self,table:String,count:u32,key:&String,param:DataTypes) -> Result<SqlResult,String>{
        let sql_query:String;
        match param {
            DataTypes::Text(ok) => sql_query = format!("SELECT * FROM {table} WHERE {key} = \'{ok}\' LIMIT {count}"),
            DataTypes::Int(ok) => sql_query = format!("SELECT * FROM {table} WHERE {key} = {ok} LIMIT {count}"),
            DataTypes::Real(ok) => sql_query = format!("SELECT * FROM {table} WHERE {key} = {ok} LIMIT {count}"),
            _ =>   return Err("unsupported".to_string()),
        }
        self.search_inner(sql_query, table,None)
    }
    pub fn search_w_n(&self,table:String,count:u32,search_names:Vec<String>) -> Result<SqlResult,String> {
        let mut new_names = Vec::new();
        let quer_names = search_names.clone();
        for x in search_names{
            new_names.push(x);
            new_names.push(",".to_string());
        };
        new_names.pop();
        let sql_query = format!("SELECT {} FROM {} LIMIT {}",new_names.into_iter().collect::<String>(),table,count);
        self.search_inner(sql_query, table,Some(quer_names))
    }

    pub fn search_w_n_where(&self,table:String,count:u32,search_names:Vec<String>,key:&String,param:DataTypes) -> Result<SqlResult,String> {
        let sql_query:String;
        let quer_names = search_names.clone();
        let mut new_names = Vec::new();
        for x in search_names{
            new_names.push(x);
            new_names.push(",".to_string());
        };
        new_names.pop();
        let search_name = new_names.into_iter().collect::<String>();
        match param {
            DataTypes::Text(ok) => sql_query = format!("SELECT {search_name} FROM {table} WHERE {key} = \"{ok}\" LIMIT {count}"),
            DataTypes::Int(ok) => sql_query = format!("SELECT {search_name} FROM {table} WHERE {key} = {ok} LIMIT {count}"),
            DataTypes::Real(ok) => sql_query = format!("SELECT {search_name} FROM {table} WHERE {key} = {ok} LIMIT {count}"),
            _ =>   return Err("unsupported".to_string()),
        }
        self.search_inner(sql_query, table,Some(quer_names))
    }


    ///orm'yi dosyaya kaydeder
    fn save_metadata(&self){
        let meta_path = &self.metadata_path;
        let mut vals =serde_json::json!([]);

        for (name ,(meta,table)) in &self.tables{

            let mut val :serde_json::Map<String,Value> = serde_json::Map::new() ;
            val.insert("name".to_string(), json!(meta.name));
            val.insert("root_path".to_string(), json!(meta.root_path));
            val.insert("db_name".to_string(), json!(meta.db_name));

            match &meta.crypted_keys {
                Some(some) => {
                    val.insert("crypted".to_string(), json!(false));
                    val.insert("crypted_keys".to_string(), json!(some));
                },
                None => {
                    val.insert("crypted".to_string(), json!(false));
                    val.insert("crypted_keys".to_string(), json!([]));
                },
            };
            val.insert("keys".to_string(), json!(table.data));
            
            vals.as_array_mut().unwrap().push(serde_json::Value::Object(val));
        }


        let data_tbw = serde_json::to_string_pretty(&vals).unwrap().as_str().to_string();
        if std::path::Path::new(&meta_path).exists(){
            let _ = std::fs::write(std::path::Path::new(&meta_path),data_tbw).unwrap();
        }else {
            let mut anc = std::path::Path::new(&meta_path).ancestors();
            anc.next();
            let _ = 
            (
                std::fs::create_dir_all(anc.next().unwrap()).map_err(|_err|  {panic!("{:?}",_err)}),
                std::fs::write(meta_path, data_tbw).map_err(|_err|  {panic!("{:?}",_err)})
            );
        }
    }

    fn connect_db(&self,val:&Lul) -> Result<Connection,String>{
        let (root_path,db_name) : (String,String);
        match val {
            Lul::Json(val) => {
                match validate_json(val) {
                    Ok(_) => (),
                    Err(err) => return Err(err),
                }
                root_path = val["root_path"].as_str().unwrap().to_string();
                db_name = val["db_name"].as_str().unwrap().to_string();
            },
            Lul::Data(lul) => {
                root_path = lul.root_path.clone();
                db_name = lul.db_name.to_owned();
            },
        }
        
        let conn :Connection;
        let db_path = format!("{}/{}",root_path,db_name);
        if Path::new(&db_path).exists(){
            conn = rusqlite::Connection::open(db_path).unwrap();
            encrpyt_database(&conn, &self.password);
            //conn.execute("sql", params)
        }else {
            let _ = std::fs::create_dir_all(Path::new(&root_path));
            let _ = std::fs::write(format!("{}{}",root_path,db_name), "");
            conn = rusqlite::Connection::open(db_path).unwrap();
            encrpyt_database(&conn, &self.password);
        }
        Ok(conn)
    }

    fn connect_db_with_name(&self,name:String) -> Result<Connection, String> {
        let (meta,STable) = self.tables.get(&name).unwrap();
        self.connect_db(&Lul::Data(meta.clone()))

    }
    


}



fn validate_json(val:&Value) -> Result<(),String>{
    let val = val.clone();
    let mut map:Vec<(&str,Option<&Value>)> = Vec::new() ;
    map.push(("root_path",      val.get("root_path")));
    map.push(("name",           val.get("name")));
    map.push(("crypted",        val.get("crypted")));
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

fn encrpyt_database(conn:&Connection,pass:&Option<Vec<u16>>){
    let _ = match pass {
        Some(som) => {
            {
                let pass = hash_str::unhash_str(som);
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
            "crypted":true,
            "crypted_keys":["password"],
            "keys":[
                {"key":"id","type":"INTEGER","constr":"PRIMARY KEY","auto":true,"name":"id"},
                {"key":"user","type":"TEXT","constr":"unique","name":"isim"},
                {"key":"password","type":"TEXT","constr":"not null","name":"şifre"},
            ]
        }
    )
}

fn hahs_str(val:&str,cost:u32) -> String {
    let buf = bcrypt::hash(val, cost).unwrap();
    let e = BASE64_STANDARD.encode(buf);
    e
}

fn get_typeof(tip:&str) -> Option<KeyTypes>{
    match tip {
        "INTEGER" | "İNTEGER" | "int" | "INT" => Some(KeyTypes::Int),
        "TEXT" | "Text" | "text" | "string" | "String" | "STRING" => Some(KeyTypes::Text),
        "REAL" | "Real" | "real" | "FLOAT" | "Float" | "float" => Some(KeyTypes::Real),
        "BLOB" | "blob" | "Blob" => Some(KeyTypes::Blob),
        "Null" | "None" | "NONE" | "NULL" => Some(KeyTypes::Null),
        _ => None
    }
}

#[derive(Debug,Serialize,Deserialize)]
pub struct SqlResult{
    key_names:HashMap<String,String>,
    values:Vec<HashMap<String,DataTypes>>
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
                    DataTypes::Blob(valx) => buf_map.insert(key.clone(), json!(valx)),
                    DataTypes::Null => buf_map.insert(key.clone(), json!(null)),
                };
            } 
            let buf = json!(buf_map);
            buf
    }
    


}

#[derive(Debug,PartialEq,Clone)]
enum KeyTypes{
    Int,
    Text,
    Real,
    Blob,
    Null
}
#[derive(Debug)]
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

mod hash_str{
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