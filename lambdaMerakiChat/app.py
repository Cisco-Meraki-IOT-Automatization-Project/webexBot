import configparser
import json
from flask import request, jsonify, render_template
import requests
import time
from chatbot import *
from control import *
from status import *

event = None
from flask_lambda import FlaskLambda
import boto3
from boto3.dynamodb.conditions import Key, Attr
import json

dynamodb2 = boto3.resource('dynamodb', region_name='us-east-2')
doctorTable = dynamodb2.Table('Doctors_Agenda')
patientTable = dynamodb2.Table('Appointment_Info')
rolesTable = dynamodb2.Table('USERINFO')

lambda_handler = FlaskLambda(__name__)


# Store credentials in a separate file
def gather_credentials():
    cp = configparser.ConfigParser()
    try:
        cp.read('credentials.ini')
        org_key = cp.get('meraki', 'key1')
        cam_key = cp.get('meraki', 'key2')
        if cam_key == '':
            cam_key = org_key
        org_id = cp.get('meraki', 'organization')
        labels = cp.get('meraki', 'cameras')
        if labels != '':
            labels = labels.split(',')
            cameras = [label.strip() for label in labels]
        else:
            cameras = []
        chatbot_token = cp.get('chatbot', 'token')
        ue = cp.get('chatbot', 'email')
        if ue != '':
            ue = ue.split(',')
            user_email = [pr.strip() for pr in ue]
        else:
            user_email = []
        lab_key = cp.get('provisioning', 'key')
        lab_org = cp.get('provisioning', 'org')
    except:
        print('Missing credentials or input file!')
        # sys.exit(2)
    return org_key, cam_key, org_id, cameras, chatbot_token, user_email, lab_key, lab_org


def webhook_meraki(webhookmeraki):
    is_card_submission = False
    is_sensor_alert = False


def newMember():
    post_message(session, headers, payload, 'welcome ' + webhook_event['data']['personDisplayName'] +
                 ', I am here to help you in whatever you need please write "menu" to get the menu :D')


# Categorize the received webhook
def typeOfMessage(webhook_event):
    # print(webhook_event)
    is_card_submission = False
    is_webex_Message = False
    is_new_member = False
    type_Hook = webhook_event['resource']
    if type_Hook == 'attachmentActions':
        is_card_submission = True
    elif type_Hook == 'messages':
        is_webex_Message = True
    elif type_Hook == 'memberships':
        is_new_member = True

    else:
        print('Warning reciving another type of msm')
    return (is_card_submission, is_webex_Message, is_new_member)


def json_response(data, response_code=200):
    response = jsonify(data)
    response.status_code = response_code
    response.headers["Content-Type"] = "application/json"
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, DELETE, PUT, PATCH, OPTIONS"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    response.headers["Access-Control-Allow-Headers"] = "authorization, x-access-token"
    response.headers["Access-Control-Request-Headers"] = "authorization, x-access-token"
    return response


@lambda_handler.route('/doctor', methods=['GET'])
def getDoctorAgenda():
    email = request.args.get('email')
    response = doctorTable.scan(FilterExpression=Attr('user_mail').eq(email))
    return response


@lambda_handler.route('/doctor', methods=['POST'])
def updateDoctor():
    id = request.args.get('id')
    rolesTable.update_item(
        Key={'id': id},
        AttributeUpdates={
            '_type': {
                'Value': 'Doctor',
                'Action': 'PUT'
            }
        },
        ReturnValues="NONE")
    return True


@lambda_handler.route('/sensors', methods=['GET'])
def getSensorsInfo():
    TABLE_NAME = "InfoSensors"
    dynamodb_client = boto3.client('dynamodb',
                                   region_name="us-east-1")
    dynamodb = boto3.resource('dynamodb', region_name="us-east-1")
    table = dynamodb.Table(TABLE_NAME)
    return table.scan()


@lambda_handler.route('/', methods=['GET'])
def root():
    TABLE_NAME = "InfoSensors"
    dynamodb_client = boto3.client('dynamodb',
                                   region_name="us-east-1")
    dynamodb = boto3.resource('dynamodb', region_name="us-east-1")
    table = dynamodb.Table(TABLE_NAME)
    response = table.scan()
    return render_template("dashboard.html", data=response)


@lambda_handler.route('/paciente', methods=['GET'])
def getPacientAgenda():
    email = request.args.get('email')
    response = patientTable.scan(FilterExpression=Attr('patient_email').eq(email))
    return response


@lambda_handler.route('/adminrole', methods=['PATCH'])
def updateAdminRole():
    id = request.args.get('id')
    apikey = request.args.get('apikey')

    rolesTable.update_item(
        Key={'id': id},
        AttributeUpdates={
            '_type': {
                'Value': 'Admin',
                'Action': 'PUT'
            },
            'apikey': {
                'Value': apikey,
                'Action': 'PUT'
            }
        },
        ReturnValues="NONE")
    return True


@lambda_handler.route('/Admin', methods=['POST'])
def admin():
    data = {
        "message": "Welcome Dashboard"
    }
    return json_response(data, response_code=200)


def typeOfMeraki(datos):
    if (datos['alertType'] == 'Sensor change detected'):
        return True
    else:
        return False


@lambda_handler.route('/WebHookMeraki', methods=['POST'])
def meraki():
    webhook_event = request.json
    sensor_change = typeOfMeraki(webhook_event)
    if sensor_change:
        sensor = checkSensorDatabase(webhook_event)
        datosDic = []
        if sensor:
            for valor in webhook_event['alertData']['triggerData']:
                datos = {'sensorValue': str(valor['trigger']['sensorValue']), 'ts': str(valor['trigger']['ts'])}
                updateValueSensor(webhook_event, datos, valor['trigger']['type'])
        else:
            for valor in webhook_event['alertData']['triggerData']:
                datosDic.append({"tipo": valor['trigger']['type'],
                                 "valores": {'sensorValue': str(valor['trigger']['sensorValue']),
                                             'ts': str(valor['trigger']['ts'])}})
            postValueSensor(webhook_event, datosDic)
        return 'true';
    else:
        print('información')
        return 'true';


# Main Lambda function
@lambda_handler.route('/WebHookWebex', methods=['POST'])
def lambda_handler2():
    webhook_event = request.json
    print(webhook_event)

    # Import user credentials
    (org_key, cam_key, org_id, cameras, chatbot_token, user_email, lab_key, lab_org) = gather_credentials()
    headers = {
        'content-type': 'application/json; charset=utf-8',
        'authorization': f'Bearer {chatbot_token}'
    }
    session = requests.Session()
    # Webhook event/metadata received, so now retrieve the actual message for the event
    # webhook_event = json.loads(event['body'])
    print(typeOfMessage(webhook_event))
    [is_card_submission, is_webex_Message, is_new_member] = typeOfMessage(webhook_event)

    chatbot_id = get_chatbot_id(session, headers)
    user_id = webhook_event['actorId']
    sender_emails = get_emails(session, user_id, headers)
    payload = {'roomId': webhook_event['data']['roomId']}
    if is_new_member:
        post_message(session, headers, payload, 'welcome ' + webhook_event['data'][
            'personDisplayName'] + ', I am here to help you in whatever you need please write "menu" to get the menu :D')
    if is_webex_Message:
        message = get_message(session, webhook_event, headers)
    # post_message(session,headers,payload,webhook_event['data']['id'])
    # Process card submissions or standard messages
    if is_card_submission:
        data = webhook_event['data']
        inputs = get_card_data(session, headers, data['id'])
        if len(inputs['inputs'].keys()) > 2:
            create_user(inputs)
            [response, dispo] = check_conection(inputs)
            if response == None:
                post_message(session, headers, payload, 'Revisa tus credenciales')
            elif (response['error_code'] == 0):
                post_message(session, headers, payload, 'Conexión correcta con TPlink! ' + response['result']['email'])
                post_message(session, headers, payload, str(dispo))
            if response['error_code'] != 0:
                post_message(session, headers, payload, 'Revisa tus credenciales')
        elif len(inputs['inputs'].keys()) == 2:
            devices = get_devicesTPLINK(payload)
            datos = []
            for device in devices:
                datos.append({"title": device, 'value': device})
            payload['attachments'] = attachList(datos, 'device')
            post_message(session, headers, payload, 'device')

        else:
            key = list(inputs['inputs'].keys())[0]
            valueM = inputs['inputs'][key]
            if key == 'GetNetworks':
                alerts = get_alerts(org_key, valueM)
                datos = []
                for alert in alerts:
                    datos.append({"title": alert['filters']['name'], 'value': alert['filters']['name']})
                payload['attachments'] = attachList(datos, 'alert')
                post_message(session, headers, payload, 'alert')
            elif key == 'Getsensors':
                datos = []
                items = getSensorsInfo()
                for item in items['Items']:
                    if item['idSensor'] == valueM:
                        for key2 in list(item.keys()):
                            if key2 != 'idSensor':
                                datos.append({"title": key2, 'value': key2 + ' ' + valueM})
                payload['attachments'] = attachList(datos, 'measure')
                post_message(session, headers, payload, 'measure')
            elif key == 'Getmeasure':
                payload['attachments'] = attachListNumber(valueM)
                post_message(session, headers, payload, valueM)

            else:
                netorks = get_networks(session, org_key, inputs['inputs'][key])
                datos = []
                for network in netorks:
                    datos.append({"title": network['id'], 'value': network['id']})
                payload['attachments'] = attachList(datos, 'Networks')
                post_message(session, headers, payload, 'netorks')

    else:
        # Stop if last message was bot's own, or else loop to infinite & beyond!
        if user_id == chatbot_id:
            return {'statusCode': 204}

        # Prevent other users from using personal bot
        elif sender_emails[0] not in user_email:
            post_message(session, headers, payload, str(sender_emails in user_email))
            post_message(session, headers, payload, str(sender_emails))
            post_message(session, headers, payload, str(user_email))

            post_message(session, headers, payload,
                         f'Hi **{get_name(session, user_id, headers)}**, I\'m not allowed to chat with you! ⛔️')
            return {'statusCode': 200}

        else:
            print(f'Message received: {message}')

        # Create & send response depending on input message
        if message_begins(message, ['hi', 'hello', 'hey', 'help', 'syn', 'test', 'meraki', '?']):
            post_message(session, headers, payload,
                         f'Hi **{get_name(session, user_id, headers)}**! _{message}_ ACKed. ✅')

            # Get org-wide device statuses
        elif message_contains(message, ['org', 'status', 'online']):
            try:
                # Yes, not PEP 8, but for the sake of modular components & CYOA...
                import status
                status.device_status(session, headers, payload, org_key)

            except ModuleNotFoundError:
                post_message(session, headers, payload, 'You need to include the **status** module first! 🙄')

                # Post camera snapshots
        elif message_contains(message, ['cam', 'photo', 'screen', 'snap', 'shot']):
            try:
                # Yes, not PEP 8, but for the sake of modular components & CYOA...
                import snapshot
                snapshot.return_snapshots(session, headers, payload, cam_key, org_id, message, cameras)

            except ModuleNotFoundError:
                post_message(session, headers, payload, 'You need to include the **snapshot** module first! 🤦')

                # Trigger webhook by changing some dashboard configuration in response to a message
        elif message_contains(message, ['disable', 'shut', 'down']):
            try:
                # Yes, not PEP 8, but for the sake of modular components & CYOA...
                import trigger
                # trigger.disable_port(session, headers, payload, cam_key)

            except ModuleNotFoundError:
                post_message(session, headers, payload, 'You need to include the **trigger** module first! 👀')

                # Undo that change to reset for next demo
        elif message_contains(message, ['enable', 'open', 'up']):
            try:
                # Yes, not PEP 8, but for the sake of modular components & CYOA...
                import trigger
                trigger.enable_port(session, headers, payload, cam_key)

            except ModuleNotFoundError:
                post_message(session, headers, payload, 'You need to include the **trigger** module first! 👀')

                # Adventure 2.0 lab, provisioning component
        elif message_contains(message, ['provision', 'deploy', 'network']):
            try:
                # Yes, not PEP 8, but for the sake of modular components & CYOA...
                import provision
                provision.get_inputs(session, headers, payload, lab_key, lab_org)

            except ModuleNotFoundError:
                post_message(session, headers, payload, 'You need to include the **provision** module first! 👀')

                # Clear screen to reset demos

        elif message_begins(message, ['clear']):
            clear_screen(session, headers, payload)
        elif message_begins(message, ['tplink']):
            dispo = get_devicesTPLINK(payload)
            post_message(session, headers, payload, 'tienes los siguientes dispositivos en tu lista: ' + str(dispo))
        elif message_begins(message, ['create_user']):
            payload['attachments'] = {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.0",
                    "body": [
                        {
                            "type": "ColumnSet",
                            "columns": [
                                {
                                    "type": "Column",
                                    "width": 2,
                                    "items": [
                                        {
                                            "type": "TextBlock",
                                            "text": "HOLA",
                                            "weight": "bolder",
                                            "size": "medium"
                                        },
                                        {
                                            "type": "TextBlock",
                                            "text": "requerimos algunos datos",
                                            "isSubtle": True,
                                            "wrap": True
                                        },

                                        {
                                            "type": "TextBlock",
                                            "text": "Your name",
                                            "wrap": True
                                        },
                                        {
                                            "type": "Input.Text",
                                            "id": "Name",
                                            "placeholder": "Alexis Rocha"
                                        },
                                        {
                                            "type": "TextBlock",
                                            "text": "Your email TPlink",
                                            "wrap": True
                                        },
                                        {
                                            "type": "Input.Text",
                                            "id": "Email",
                                            "placeholder": "john.andersen@example.com",
                                            "style": "email"
                                        },
                                        {
                                            "type": "TextBlock",
                                            "text": "Your password",
                                            "wrap": True
                                        },
                                        {
                                            "type": "Input.Text",
                                            "id": "Password",
                                            "placeholder": "contraseña",
                                            "style": "text"
                                        }
                                    ]
                                },
                                {
                                    "type": "Column",
                                    "width": 1,
                                    "items": [
                                        {
                                            "type": "Image",
                                            "url": "https://www.password.mx/wp-content/uploads/2020/09/meraki-license.jpg",
                                            "size": "auto"
                                        }
                                    ]
                                }
                            ]
                        }
                    ],
                    "actions": [
                        {
                            "type": "Action.Submit",
                            "title": "Submit",
                            "id": "Formulario"
                        }
                    ]
                },
                "type": "AdaptiveCard",
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "version": "1.2"
            }
            post_message(session, headers, payload,
                         'Crearemos un nuevo usuario! 👀 porfavor ingrese sus credenciales para la nuve tplink')
        elif message_begins(message, ['check red']):
            [response, dispo] = check_conection(payload)
            if response == None:
                post_message(session, headers, payload, 'Revisa tus credenciales')
            elif (response['error_code'] == 0):
                post_message(session, headers, payload, 'Conexión correcta con TPlink! ' + response['result']['email'])
                post_message(session, headers, payload, str(dispo))
            if response['error_code'] != 0:
                post_message(session, headers, payload, 'Revisa tus credenciales')
        elif message_begins(message, ['admin']):
            post_message(session, headers, payload, str(user_email))
            post_message(session, headers, payload, message)

        elif message_begins(message, ['device']):
            post_message(session, headers, payload, str(type(message)))
            post_message(session, headers, payload, message.split(' ')[1])
            # elif message_begins(message, ['alertas']):
            #   alertas = get_alertas(org_key,message)
            post_message(session, headers, payload, str(alertas))
        elif message_begins(message, ['conectar']):
            x = check_conection(payload)
            post_message(session, headers, payload, str(x))
        elif message_begins(message, ['menu']):
            post_message(session, headers, payload,
                         'Menu del día\n alertas (--filter)\n conectar\nmenu\ndevice\ncreate_user\nclear\ntplink')
        elif message_begins(message, ['table_sensors']):
            datos = getSensorsInfo()
            for item in datos['Items']:
                val = ''
                for key in item.keys():
                    try:
                        val = val + ' ' + key + ' valor :' + item[key][-1][
                            'sensorValue'] + ' con fecha :' + time.strftime('%Y-%m-%d %H:%M:%S',
                                                                            time.localtime(float(item[key][-1]['ts'])))
                    except:
                        val = val + ' sensor :' + str(item[key])
                post_message(session, headers, payload, val)


        elif message_begins(message, 'assign_sensors'):
            datos = getSensorsInfo()
            dic = []
            for item in datos['Items']:
                dic.append({"title": item['idSensor'], 'value': item['idSensor']})
            payload['attachments'] = attachList(dic, 'sensors')
            post_message(session, headers, payload, 'Sensor')

            # for sensor in sensors:
            #
            #


        elif message_begins(message, ['alerts']):
            orgs = get_organizations2(session, org_key)

            datos = []

            for org in orgs:
                datos.append({"title": org['name'], 'value': org['id']})

            payload['attachments'] = attachList(datos, 'Organizacion')

            post_message(session, headers, payload, 'hola')

            '''
            final = message.split(' ')
            post_message(session, headers, payload, final[1])
            post_message(session, headers, payload, final[2])
            post_message(session, headers, payload, final[3])
            post_message(session, headers, payload, final[4])
            '''
            # Catch-all if bot doesn't understand the query!
        else:
            post_message(session, headers, payload, 'Make a wish! 🤪')

        # Let chat app know success
    return {
        'statusCode': 200,
        'body': json.dumps('message received')
    }


if __name__ == '__main__':
    lambda_handler.run(debug=True)