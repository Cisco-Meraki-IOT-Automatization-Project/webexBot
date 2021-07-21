from chatbot import *
import boto3
from tplinkcloud import TPLinkDeviceManager
import requests
import json

base_url = 'https://api.meraki.com/api/v0'
_bURL = 'https://api.meraki.com/api/v1'
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('InfoCredentials')
table2 = dynamodb.Table('InfoSensors')


def checkSensorDatabase(datos):
    print(datos['deviceName'])
    campo = table2.get_item(Key={'idSensor': datos['deviceName']})
    try:
        campo['Item']
        return True
    except KeyError:
        return False
    except:
        print('Revisar sensor ' + datos['deviceName'])
        return False


def postValueSensor(datos, valores):
    Item = {"idSensor": datos['deviceName']}
    for val in valores:
        Item[val['tipo']] = [val['valores']]
    response = table2.put_item(Item=Item)


def attachList(datos, id):
    return {

        "contentType": "application/vnd.microsoft.card.adaptive",
        "content": {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.0",
            "body": [
                {
                    "type": "Input.ChoiceSet",
                    "choices": datos,
                    "placeholder": id,
                    "id": "Get" + id
                }
            ],

            "actions": [
                {
                    "type": "Action.Submit",
                    "title": "Submit",
                    "id": id
                }
            ]}
    }


def attachListNumber(id):
    return {

        "contentType": "application/vnd.microsoft.card.adaptive",
        "content": {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.2",
            "body": [
                {
                    "type": "Input.Number",
                    "placeholder": str(id) + 'On',
                    "id": "Get" + str(id) + "On",
                    "value": 0,
                    "min": -30,
                    "max": 30

                },
                {
                    "type": "Input.Number",
                    "placeholder": str(id) + 'Off',
                    "id": "Get" + str(id) + "Off",
                    "value": 0,
                    "min": -30,
                    "max": 30

                }
            ],

            "actions": [
                {
                    "type": "Action.Submit",
                    "title": "Submit",
                    "id": id
                }
            ]}
    }


def updateValueSensor(datos, valores, tipo):
    response = table2.update_item(Key={'idSensor': datos['deviceName']},
                                  UpdateExpression="SET " + tipo + " = list_append(" + tipo + ", :i)",
                                  ExpressionAttributeValues={
                                      ':i': [valores]
                                  })


def create_user(datos):
    response = table.put_item(Item={"id": datos['roomId'],
                                    "tplinkEmail": datos['inputs']['Email'],
                                    "contrasena": datos['inputs']['Password']
                                    })


def get_admins(datos):
    response = table.get_item(Key={'id': datos['roomId']})['Item']
    x = None
    try:
        x = response['admins']
    except:
        pass
    return x


def add_admins(datos, valores):
    response = table.update_item(Key={'id': datos['roomId']},
                                 UpdateExpression="SET admins = list_append(admins, :i)",
                                 ExpressionAttributeValues={
                                     ':i': [valores]
                                 })


def get_devicesTPLINK(datos):
    response = table.get_item(Key={'id': datos['roomId']})['Item']
    device_manager = TPLinkDeviceManager(response['tplinkEmail'], response['contrasena'])
    devices = device_manager.get_devices()
    dispo = []
    if devices:
        for device in devices:
            dispo.append(device.get_alias())
    return dispo;


def check_conection(datos):
    responseTp = None
    devices = []
    try:
        response = table.get_item(Key={'id': datos['roomId']})['Item']
        username = response['tplinkEmail']
        password = response['contrasena']
        body = {
            'method': 'login',
            'url': 'https://wap.tplinkcloud.com/',
            'params': {
                'appType': 'Kasa_Android',
                'cloudUserName': username,
                'cloudPassword': password,
                'terminalUUID': '3sd23'
            }
        }
        responseTp = requests.post('https://wap.tplinkcloud.com/', data=json.dumps(body)).json()
        device_manager = TPLinkDeviceManager(username, password)
        devices2 = device_manager.get_devices()
        if devices2:
            for device in devices2:
                devices.append(device.get_alias())
    except:
        pass
    return responseTp, devices;