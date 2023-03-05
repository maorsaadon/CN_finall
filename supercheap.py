from typing import Union
import requests
from fastapi import FastAPI
import sched, time
from threading import Thread
import asyncio
from modules.signup import SignUp
from modules.signin import SignIn
from modules.mysuper import MySuper
from modules.myaccount import MyAccount
from modules.addcomment import AddComment
from modules.displaycomment import DisplayComment
from modules.displaysales import DisplaySales
from modules.homeagep import HomePage
from modules.InsertItem import InsertItem
from modules.DeleteItem import DeleteItem
from modules.DeleteSale import DeleteSale
from modules.dosale import DoSale
from modules.IsCity import IsCity
from modules.IsItem import IsItem

from modules.display_super import DisplaySuper

app = FastAPI()


# //////////////////////michael////////////////////////////
@app.get("/signin")
async def get_sighin_user(username: str, password: str):
    mySingIn = SignIn(username, password)
    return mySingIn.dosighin()


@app.get("/mysuper/getsuper")
async def get_super_info(Super_Id: str):
    tempMySuper = MySuper(Super_Id)
    return tempMySuper.get_super()


@app.get("/mysuper/setsuper")
async def set_super_info(Super_Id: str, super_name: str, super_city: str):
    tempMySuper = MySuper(Super_Id)
    old_super = tempMySuper.get_super()
    ansswer = tempMySuper.set_super(super_name, super_city)
    if super_city != old_super.get("super_city"):
        tempMySuper.moveSuper(old_super.get("super_city"), super_city)
    return ansswer


@app.get("/myaccount/setuser")
async def my_acc_set_user(first_name: str, last_name: str, email: str, username: str, password: str, city: str,
                          birth_date: str, gender: str, is_manager: str, super_id: str):
    temp_account = MyAccount({'first_name': first_name, 'last_name': last_name, 'email': email, 'username': username,
                              'password': password, 'city': city, 'birth_date': birth_date, 'gender': gender,
                              'is_manager': is_manager,
                              'super_id': super_id})
    return temp_account.change_user()


@app.get("/addcomment")
async def add_comment(id_comment: str, super_name: str, super_city: str, user_username: str, grade, review: str):
    tempaddComment = AddComment(
        {'id_comment': id_comment, 'super_name': super_name, 'super_city': super_city, 'user_username': user_username,
         'grade': grade, 'review': review})
    return tempaddComment.addCommentToDataBase()


@app.get("/displaycomment")
async def display_comment(super_name: str, super_city: str):
    temp_displaycomment = DisplayComment({"super_name": super_name, "super_city": super_city})
    return temp_displaycomment.getCommentsfromDataBase()


@app.get("/displaysale")
async def display_sale(super_name: str, super_city: str):
    temp_displaysale = DisplaySales({"super_name": super_name, "super_city": super_city})
    return temp_displaysale.getSalesfromDataBase()


@app.get("/getnewcomments")
async def get_New_Commenst(super_ID: str):
    temp_HomePage = HomePage({"super_ID": super_ID})
    return temp_HomePage.getcomments()


# //////////////////////eylon////////////////////////////


# http://localhost:5000/
@app.get("/")
async def read_root():
    return {"Hello": "World"}


# http://localhost:5000/test
@app.get("/test")
def read_root():
    return {"Hello": "test"}


# http://localhost:5000/signup/user?first_name=eylon&last_name=naamat&email=emailll&username=test&password=getPassword&city=getCity&birth_date=getBirth_date&gender=getGender&is_manager=michael&super_id=getSuper_id
@app.get("/signup/user")
async def get_user(first_name: str, last_name: str, email: str, username: str, password: str, city: str,
                   birth_date: str, gender: str, is_manager: str, super_id: str):
    USER = {'first_name': first_name, 'last_name': last_name, 'email': email, 'username': username,
            'password': password, 'city': city, 'birth_date': birth_date, 'gender': gender, 'is_manager': is_manager,
            'super_id': super_id}

    sign_up = SignUp(USER, {})

    insertion_status = sign_up.insert_user()

    return insertion_status


# http://localhost:5000/signup/super?super_ID=123456&super_name=hatzlaha&super_city=Ariel
@app.get("/signup/super")
async def get_super(super_ID: str, super_name: str, super_city: str, comments_size: str, super_rating: str):
    SUPER = {'super_ID': super_ID, 'super_name': super_name, 'super_city': super_city,
             'comments_size': comments_size, 'super_rating': super_rating}

    sign_up = SignUp({}, SUPER)

    insertion_status = sign_up.insert_super_to_fb()

    return insertion_status


# http://localhost:5000/signup/city?super_ID=123456&super_name=hatzlaha&super_city=Ariel
@app.get("/signup/city")
async def get_city(super_ID: str, super_name: str, super_city: str, comments_size: str, super_rating: str):
    SUPER = {'super_ID': super_ID, 'super_name': super_name, 'super_city': super_city,
             'comments_size': comments_size, 'super_rating': super_rating}

    sign_up = SignUp({}, SUPER)

    insertion_status = sign_up.insert_city_to_fb()

    return insertion_status


# http://localhost:5000/displaysuper?city=ariel&itemlist=bira_3-corona,shampoo-dove
@app.get("/displaysuper")
async def get_supers(city: str, itemlist: str):
    display_super = DisplaySuper(city, itemlist)

    to_display = display_super.get_supers()

    return to_display


# ///////////////// Ben/////////////////////////////
@app.get("/addItem")
async def additem(itemname: str, price: str, company: str, super_id: str):
    ITEM = {'item_name': itemname, 'price': price, 'company': company, 'super_id': super_id}

    insert_item = InsertItem(ITEM)

    return insert_item.insert_item_to_FB()


@app.get("/deleteItem")
async def delete_item(itemname: str, company: str, super_id: str):
    ITEM = {'item_name': itemname, 'company': company, 'super_id': super_id}

    delete_item = DeleteItem(ITEM)

    return delete_item.delete_item_from_FB()


@app.get("/deleteSale")
async def delete_sale(sale_name: str, super_id: str):
    SALE = {'sale_name': sale_name, 'super_id': super_id}

    delete_sale = DeleteSale(SALE)

    return delete_sale.delete_sale_from_FB()


@app.get("/DoSale")
def dosale(item_name: str, saleQuantity: str, priceSale: str, company: str, sale_name: str, super_id: str):
    SALE = {'item_name': item_name, 'saleQuantity': saleQuantity, 'priceSale': priceSale, 'company': company,
            'sale_name': sale_name, 'super_id': super_id}

    do_sale = DoSale(SALE)

    return do_sale.insert_sale_to_FB()


@app.get("/IsCity")
def Is_city(city_name: str):
    CITY = {'city_name': city_name}

    is_city = IsCity(CITY)
    return is_city.get_iscity()


@app.get("/IsItem")
def Is_city(item_name: str):
    ITEM = {'item_name': item_name}
    is_item = IsItem(ITEM)
    return is_item.get_isitem()
    # ///////////////////////////////////////////////////