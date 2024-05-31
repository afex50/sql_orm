use std::{collections::HashMap, fmt::format, path::Path};

use rusqlite::{params, Connection};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use base64::prelude::*;

use crate::others::{encrpyt_database, get_typeof, hahs_str, hash_string, validate_json, DataTypes, KeyTypes, SqlGeneric, SqlResult, UnionSearchQuery, UnionSearchthing};

#[macro_export]
macro_rules! new_table {
    () => {
        
        {
            json!(
                {
                    "name":"users",
                    "root_path":"./root/path/to/database/",
                    "db_name":"database_name.db",
                    "crypted_keys":[],
                    "keys":[
//                      {"key":"id","type":"INTEGER","constr":"PRIMARY KEY","auto":true,"name":"id"},
//                      {"key":"user","type":"TEXT","constr":"unique","name":"isim"},
//                      {"key":"password","type":"TEXT","constr":"not null","name":"şifre"},
                    ]
                }
            )
        }
    };
}

/// salt:bcrypt için şifre, pass:veritabanı şifresi
/// 
/// 
#[derive(Debug,Serialize,Deserialize)]
pub struct SqlOrm{
    password:Option<Vec<u16>>,
    metadata_path:String,
    tables:HashMap<String,(TableMeta,SqlTable)>,
    bcrypt_cost:u32
}



#[derive(Eq, Hash, PartialEq,Debug,Clone,Serialize,Deserialize)]
pub struct TableMeta{
    name:String,
    root_path:String,
    db_name:String,
    crypted_keys:Option<Vec<String>>
}
impl TableMeta {
    pub fn dump_cypted_keys(&self) -> &Option<Vec<String>> {
        &self.crypted_keys
    }
}

///  keys stored in here
/// ```
/// [{"key":"id","value":"INTEGER AUTO INCREMENT","auto":true,"type":"INTEGER"},...]
/// ```
#[derive(Debug,Serialize,Deserialize)]
pub struct SqlTable{
    pub data:Value
}


pub enum SqlErr{
    DbNotFound(String),
}

#[derive(Debug,Clone)]
enum Lul {
    Json(Value),
    Data(TableMeta),
    Path(String)
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

    pub fn orm_to_json(&self) -> Value {
        serde_json::to_value(self).unwrap()
    }

    ///vay amk  
    /// bu bi yorum
    pub fn init<S:Into<String>>(pass:Option<S>,meta_path:S,bcrypt_cost:u32) -> Self{
        let meta_path = &meta_path.into();
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
            
            let buf = SqlTable{data:row.get("keys").unwrap().clone()};
            tables.insert( row.get("name").unwrap().as_str().unwrap().to_string(),(meta_buf,buf) );
            counter += 1;
        }
        let pass = {
            match pass {
                Some(som) => Some(hash_string::hash_str(som.into())),
                None => None,
            }
        };
        
        let mut orm = Self{
            metadata_path:meta_path.to_string(),
            password:pass,
            tables:tables,
            bcrypt_cost:bcrypt_cost
        };
        orm.new_table(val);
        orm
    }
    pub fn new_table(
        &mut self,
        mut val:Value
    ) -> Result<(),String>{
        
        let mut count = 0;
        if val.is_array(){
            count = val.clone().as_array().unwrap().len();
        }else {
            count = 1;
            val = json!([val]);
        }
        for x in 0..count{
            //println!("val[0] : {:?}",val[0]);
            let val = &val[0];
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
            count+=1;
        }
        Ok(())
    }


    pub fn dump_tables(&self) -> &HashMap<String, (TableMeta, SqlTable)>{
        &self.tables
    }

    /// drops the table
    pub fn remove_table<S:Into<String>>(&mut self,table_name:S) -> Result<(), String>{
        let table_name = table_name.into();
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
                self.save_metadata();
                return Ok(());
            },
            Err(err) => {
                return Err(format!("error dropping table from sql {}",err));
            },
        };
    }



    pub fn insert_generic<T,S:Into<String>>(&self,table:S,generic:SqlGeneric<T>) -> Result<(),String> where T : Serialize{
        let table = table.into();
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
    pub fn insert<S:Into<String>>(&self,table:S,val:Value) -> Result<(),String>{
        let table = table.into();
        let meta;
        let tables;
        if let Some((met,tab)) = self.tables.get(&table){
            meta = met;
            tables = tab
        }else {
            return Err("Table not found".to_string());
        }

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
            let dat = (key,get_typeof(ktype).unwrap());
            //println!("{:?}",dat);
            keys.push(dat);

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
                    let mut valu = valu.clone();
                    if valu.is_array(){
                        
                        let val2 = valu.clone();
                        let mut vec = Vec::with_capacity(val2.as_array().unwrap().len());
                        for x in val2.as_array().unwrap(){
                            match x.as_u64() {
                                Some(som) => {vec.push(som as u8)},
                                None => return Err("Blobda hata".to_string()),
                            }
                        }
                        let str = BASE64_STANDARD.encode(vec);
                        valu = json!(str)
                        
                    }    
                    let mut valx = valu.as_str().unwrap().to_string();
                    for x in &meta.crypted_keys{
                        if x.contains(key){
                            let e = hahs_str(valu.as_str().unwrap(),self.bcrypt_cost).to_string();
                            valx = e.clone();
                        }
                    }
                    if keys.contains(&(key.as_str(),KeyTypes::Text))  {
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

                    }else if keys.contains(&(key.as_str(),KeyTypes::Blob)) {
                        key_names.push(key.to_string());
                        key_names.push(",".to_string());
                        values.push("'".to_string());
                        values.push(valx);
                        values.push("'".to_string());
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
                let mut valu = valu.clone();
                if valu.is_array(){
                    
                    let val2 = valu.clone();
                    let mut vec = Vec::with_capacity(val2.as_array().unwrap().len());
                    for x in val2.as_array().unwrap(){
                        match x.as_u64() {
                            Some(som) => {vec.push(som as u8)},
                            None => return Err("Blobda hata".to_string()),
                        }
                    }
                    let str = BASE64_STANDARD.encode(vec);
                    valu = json!(str)
                    
                }
                let mut valx = valu.as_str().unwrap().to_string();
                for x in &meta.crypted_keys{
                    if x.contains(key){
                        let e = hahs_str(valu.as_str().unwrap(),self.bcrypt_cost).to_string();
                        valx = e.clone();
                    }
                }
                //println!("key : {} , valx:{}",&key,valx);
                //println!("{:?}",keys);
                if keys.contains(&(key.as_str(),KeyTypes::Text)) || keys.contains(&(key.as_str(),KeyTypes::Blob)){
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
                //println!("{} ok",key );
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

    ///no search command 
    fn custom_command<S:Into<String>>(&self,table:S,query:S) -> Result<(), String>{
        let meta;
        let STable;
        if let Some((met,tab)) = self.tables.get(&table.into()){
            meta = met;
            STable = tab;
        }else {
            return Err("Table not found".to_string());
        }
        
        let conn:Connection = match self.connect_db(&Lul::Data(meta.clone())){
            Ok(ok) => ok,
            Err(err) => return Err(err),
        };
        match conn.execute(&query.into(), params![]) {
            Ok(ok) => return Ok(()),
            Err(err) => return Err(format!("{}",err)),
        }
    }

    fn search_inner(&self,sql_query:String,table:String,search_names:Option<Vec<String>>) ->Result<SqlResult,String> {
        let meta;
        let STable;
        if let Some((met,tab)) = self.tables.get(&table){
            meta = met;
            STable = tab
        }else {
            return Err("Table not found".to_string());
        }
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

        //println!("{}",sql_query);
        let query = sql_query;
        let mut stmt = conn.prepare(&query).map_err(|err| {return format!("{:?}",err);})?;
        let mut rows = stmt.query([]).map_err(|err| {return format!("{:?}",err);})?;


    
        match &search_names {
            Some(som) => {
                let mut old = keyname_types.clone();
                keyname_types = Vec::new();
                for x in som {
                    let mut ok = false;
                    for (k,t) in &old {
                        //println!("x: {}, k: {}",x,k);
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
                    KeyTypes::Int =>  DataTypes::Int(row.get(counter). map_err(|err| {return format!("{:?}",err);})?),
                    KeyTypes::Text => DataTypes::Text(row.get(counter).map_err(|err| {return format!("{:?}",err);})?),
                    KeyTypes::Real => DataTypes::Real(row.get(counter).map_err(|err| {return format!("{:?}",err);})?),
                    KeyTypes::Blob => DataTypes::Blob({
                        let e :String = row.get(counter).map_err(|err| {return format!("{:?}",err);})?;
                        BASE64_STANDARD.decode(e).map_err(|err| {return format!("{:?}",err);})?
                        
                    }),
                    KeyTypes::Null => DataTypes::Null,
                };
                //println!("{:?}",rowdata);
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

    //blob and null unsupported
    pub fn search_where<S:Into<String>>(&self,table:S,count:u32,key:S,param:DataTypes) -> Result<SqlResult,String>{
        let (table,key) = (table.into(),&key.into());
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

    pub fn search_w_n_where<S:Into<String>,T:Into<String>,U:Into<String>>(&self,table:S,count:u32,search_names:Vec<T>,key:U,param:DataTypes) -> Result<SqlResult,String> {
        let table = table.into();
        let key = key.into();
        let search_names = {
            let mut vec = vec![];
            for x in search_names{
                vec.push(x.into());
            }
            vec
        };
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



    fn union_search_inner(&self,tables:Vec<String>,count:u32,_where:Option<String>,) -> Result<SqlResult,String>{
        /*kontrol*/{
            let mut tables_not_found= Vec::new();
            'a:for y in &tables{
                for (x,_) in self.dump_tables(){
                    if x == y{
                        continue 'a;
                    }
                }
                tables_not_found.push(y.clone());
                tables_not_found.push(", ".to_string());

            }
            if !tables_not_found.is_empty(){
                tables_not_found.pop();
                return Err(format!("tables not found :{}",tables_not_found.concat()));
            }
        }
        // let mut table_with_db = HashMap::<String,Vec<Value>>::new();
        // for (table,e) in self.dump_tables(){
        //     if tables.contains(table) && table_with_db.is_empty(){
        //         for x in e.1.data.as_array().unwrap(){
        //             table_with_db.insert(format!("{}{}",x.get("root_path").unwrap().as_str().unwrap(),x.get("db_name").unwrap().as_str().unwrap()), vec![x.clone()]);
        //         }
        //     }
        //     let mut new_fields = Vec::<Value>::new();
        //     if tables.contains(table){
        //          for l in table_with_db.get_mut(&format!("{}{}",e.1.data.get("root_path").unwrap().as_str().unwrap(),e.1.data.get("db_name").unwrap().as_str().unwrap())){
        //             for _x in l{
        //                 for _y in e.1.data.as_array().unwrap(){
        //                     if _x == _y{
        //                         new_fields.push(_x.clone())
        //                     }
        //                 }
        //             }
        //             l = &mut new_fields;
        //         }
        //     }
        // }
        // let mut querys = Vec::<String>::new();
        // let same_keys = {
        //     let mut keys = Vec::<String>::new();
        //     for x in same_fields{
        //         keys.push(x
        //                 .as_object()
        //                 .unwrap()
        //                 .get("key")
        //                 .unwrap()
        //                 .as_str()
        //                 .unwrap()
        //                 .to_string());
        //         keys.push(",".to_string());
        //     }
        //     keys.pop();
        //     keys.concat()
        // };
        // key=path val = {table_name,keys}

        let same_keys={
            let mut same_tables = Vec::new();
            for (table,e) in self.dump_tables(){
                if tables.contains(table) && same_tables.is_empty(){
                    for x in e.1.data.as_array().unwrap(){
                        same_tables.push(x.clone());
                    }
                }
                let mut new_fields = Vec::<Value>::new();
                if tables.contains(table){
                        for _x in &same_tables{
                            for _y in e.1.data.as_array().unwrap(){
                                if _x == _y{
                                    new_fields.push(_x.clone())
                                }
                            }
                        
                    }
                    same_tables = new_fields.clone();
                }
            }
            // println!("{:#?}",same_tables);
            same_tables
        };


        let mut search_names:Vec<String> = Vec::new(); 

        let search_keys = {
            let mut kys = Vec::new();
            for x in &same_keys{
                kys.push(x.get("key").unwrap().as_str().unwrap());
                search_names.push(x.get("name").unwrap().as_str().unwrap().to_string());
                kys.push(",");
            }
            kys.pop();
            kys.concat()
        };

        let mut table_with_db = HashMap::<String,Vec<UnionSearchthing>>::new();
        for x in tables{
            let a = self.tables.get(&x).unwrap();
            let path = format!("{}{}",a.0.root_path,a.0.db_name);
            if table_with_db.contains_key(&path){
                table_with_db.get_mut(&path).unwrap().push(UnionSearchthing{table:x,keys:a.1.data.clone()})
            }
            else {
                table_with_db.insert(path, vec![UnionSearchthing{table:x,keys:a.1.data.clone()}]);
            }
        }

        let mut queries = Vec::<UnionSearchQuery>::new();
        for (path,thing) in table_with_db{
            let mut master_query=Vec::new();
            for x in thing{
                let query = format!("select {} from {} count {count} {}",search_keys,x.table,_where.clone().unwrap_or("".to_string()));
                master_query.push(query);
                master_query.push(" union ".to_string());
            }
            master_query.pop();
            queries.push(UnionSearchQuery::new(path, master_query.concat()));
        }
        let mut results = Vec::<SqlResult>::new();
        println!("{:#?}",queries);
        for x in queries{
            let conn = self.connect_db(&Lul::Path(x.path)).map_err(|err| format!("{}",err))?;
        }


        // let conn = Connection::open(Path::new())

        todo!()
    }
    pub fn union_search(&self,tables:Vec<String>,count:u32){
        self.union_search_inner(tables, count, None).unwrap();
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
                    val.insert("crypted_keys".to_string(), json!(some));
                },
                None => {
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
            Lul::Path(String) => {
                let pth = Path::new(&String);
                let mut a = pth.ancestors();
                let _a :Vec<u8>= pth.file_name().unwrap().to_str().unwrap().bytes().collect();
                let str = String::from_utf8(_a).unwrap();
                db_name = str;             
                root_path = {
                    let a = a.next().unwrap().to_str().unwrap();
                    String::from_utf8(a.bytes().collect::<Vec<u8>>()).unwrap()
                };
            },
        }
        
        let conn :Connection;
        let db_path = format!("{}/{}",root_path,db_name);
        if Path::new(&db_path).exists(){
            conn = rusqlite::Connection::open(db_path).map_err(|e| format!("{}",e))?;
            encrpyt_database(&conn, &self.password);
            //conn.execute("sql", params)
        }else {
            let _ = std::fs::create_dir_all(Path::new(&root_path));
            let _ = std::fs::write(format!("{}{}",root_path,db_name), "");
            conn = rusqlite::Connection::open(db_path).map_err(|e| format!("{}",e))?;
            encrpyt_database(&conn, &self.password);
        }
        Ok(conn)
    }

    fn connect_db_with_table_name(&self,name:String) -> Result<Connection, String> {
        let (meta,STable) = self.tables.get(&name).unwrap();
        self.connect_db(&Lul::Data(meta.clone()))

    }

}

