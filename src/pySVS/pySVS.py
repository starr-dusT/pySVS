#!/usr/bin/python3 

import asyncio
from binascii import crc_hqx, hexlify, unhexlify
from bleak import BleakClient
import getopt
import platform
import requests
import sys
from threading import Thread
import time
import traceback

###################    SB-1000-PRO CONFIG    ###################

#SERV01 = "0000fef6-0000-1000-8000-00805f9b34fb"
#CHAR11 = "005f0005-2ff2-4ed5-b045-4c7463617865"
#CHAR12 = "005f0004-2ff2-4ed5-b045-4c7463617865"
#CHAR13 = "005f0003-2ff2-4ed5-b045-4c7463617865"
#CHAR14 = "005f0002-2ff2-4ed5-b045-4c7463617865"

#SERV02 = "1fee6acf-a826-4e37-9635-4d8a01642c5d"
#CHAR21 = "7691b78a-9015-4367-9b95-fc631c412cc6"
CHAR22 = "6409d79d-cd28-479c-a639-92f9e1948b43"

#SERV03 = "0000180a-0000-1000-8000-00805f9b34fb"
#CHAR31 = "00002a29-0000-1000-8000-00805f9b34fb"
#CHAR32 = "00002a25-0000-1000-8000-00805f9b34fb"

#SERV04 = "00001801-0000-1000-8000-00805f9b34fb"
#CHAR41 = "00002a05-0000-1000-8000-00805f9b34fb"

FRAME_PREAMBLE = b'\xaa'

SVS_FRAME_TYPES = {
        "PRESETLOADSAVE": b'\x07\x04',
        "MEMWRITE": b'\xf0\x1f', 
        "MEMREAD": b'\xf1\x1f',
        "READ_RESP": b'\xf2\x00',
        "RESET": b'\xf3\x1f',
        "SUB_INFO1": b'\xf4\x1f',
        "SUB_INFO1_RESP": b'\xf5\x00',
        "SUB_INFO2": b'\xfc\x1f',
        "SUB_INFO2_RESP": b'\xfd\x00',
        "SUB_INFO3": b'\xfe\x1f',
        "SUB_INFO3_RESP": b'\xff\x00'
        }

SVS_PARAMS = {
        "FULL_SETTINGS":{"id":4, "offset":0x0, "limits": [None], "limits_type":"group", "n_bytes":52, "reset_id": -1 }, #group
        "DISPLAY":{"id":4, "offset":0x0, "limits": [0,1,2], "limits_type":1, "n_bytes":2, "reset_id": 0 },  #discrete
        "DISPLAY_TIMEOUT":{"id":4, "offset":0x2,"limits": [0,10,20,30,40,50,60], "limits_type":1, "n_bytes":2, "reset_id": 1 }, #discrete
        "STANDBY":{"id":4, "offset":0x4, "limits": [0,1,2], "limits_type":1, "n_bytes":2, "reset_id": 2 }, #discrete
        "BRIGHTNESS":{"id":4, "offset":0x6, "limits": [0,1,2,3,4,5,6,7], "limits_type":1, "n_bytes":2, "reset_id": 14 }, #discrete
        "LOW_PASS_FILTER_ALL_SETTINGS":{"id":4, "offset":0x8, "limits": [None], "limits_type":"group", "n_bytes":6, "reset_id": 3 }, #group
        "LOW_PASS_FILTER_ENABLE":{"id":4, "offset":0x8, "limits": [0,1], "limits_type":1, "n_bytes":2, "reset_id": 3 }, #discrete
        "LOW_PASS_FILTER_FREQ":{"id":4, "offset":0xa, "limits": [30, 200], "limits_type":0, "n_bytes":2, "reset_id": 3 }, #continous
        "LOW_PASS_FILTER_SLOPE":{"id":4, "offset":0xc,"limits": [6, 12, 18, 24], "limits_type":1, "n_bytes":2, "reset_id": 3 }, #discrete
        "PEQ1_ALL_SETTINGS":{"id":4, "offset":0xe,"limits": [None], "limits_type":"group", "n_bytes":8, "reset_id": 5 }, #group
        "PEQ1_ENABLE":{"id":4, "offset":0xe,"limits": [0,1], "limits_type":1, "n_bytes":2, "reset_id": 5 }, #discrete
        "PEQ1_FREQ":{"id":4, "offset":0x10,"limits": [20,200], "limits_type":0, "n_bytes":2, "reset_id": 5 }, #continous
        "PEQ1_BOOST":{"id":4, "offset":0x12,"limits": [-12.0,6.0], "limits_type":0, "n_bytes":2, "reset_id": 5 }, #continous
        "PEQ1_QFACTOR":{"id":4, "offset":0x14,"limits": [0.2,10.0], "limits_type":0, "n_bytes":2, "reset_id": 5 }, #continous
        "PEQ2_ALL_SETTINGS":{"id":4, "offset":0x16,"limits": [None], "limits_type":"group", "n_bytes":8, "reset_id": 5 }, #group
        "PEQ2_ENABLE":{"id":4, "offset":0x16,"limits": [0,1], "limits_type":1, "n_bytes":2, "reset_id": 5 }, #discrete
        "PEQ2_FREQ":{"id":4, "offset":0x18,"limits": [20,200], "limits_type":0, "n_bytes":2, "reset_id": 5 }, #continous
        "PEQ2_BOOST":{"id":4, "offset":0x1a,"limits": [-12.0,6.0], "limits_type":0, "n_bytes":2, "reset_id": 5 }, #continous
        "PEQ2_QFACTOR":{"id":4, "offset":0x1c,"limits": [0.2,10.0], "limits_type":0, "n_bytes":2, "reset_id": 5 }, #continous
        "PEQ3_ALL_SETTINGS":{"id":4, "offset":0x1e,"limits": [None], "limits_type":"group", "n_bytes":8, "reset_id": 5 }, #group
        "PEQ3_ENABLE":{"id":4, "offset":0x1e,"limits": [0,1], "limits_type":1, "n_bytes":2, "reset_id": 5 }, #discrete
        "PEQ3_FREQ":{"id":4, "offset":0x20,"limits": [20,200], "limits_type":0, "n_bytes":2, "reset_id": 5 }, #continous
        "PEQ3_BOOST":{"id":4, "offset":0x22,"limits": [-12.0,6.0], "limits_type":0, "n_bytes":2, "reset_id": 5 }, #continous
        "PEQ3_QFACTOR":{"id":4, "offset":0x24,"limits": [0.2,10.0], "limits_type":0, "n_bytes":2, "reset_id": 5 }, #continous
        "ROOM_GAIN_ALL_SETTINGS":{"id":4, "offset":0x26, "limits": [None], "limits_type":"group", "n_bytes":6, "reset_id": 8 }, #group
        "ROOM_GAIN_ENABLE":{"id":4, "offset":0x26, "limits": [0,1], "limits_type":1, "n_bytes":2, "reset_id": 8}, #discrete
        "ROOM_GAIN_FREQ":{"id":4, "offset":0x28, "limits": [25, 31, 40], "limits_type":1, "n_bytes":2, "reset_id": 8 }, #discrete
        "ROOM_GAIN_SLOPE":{"id":4, "offset":0x2a, "limits": [6,12], "limits_type":1, "n_bytes":2, "reset_id": 8 }, #discrete
        "VOLUME": {"id":4, "offset":0x2c, "limits": [-60,0], "limits_type":0, "n_bytes":2, "reset_id": 12 }, #continous
        "PHASE": {"id":4, "offset":0x2e, "limits": [0,180], "limits_type":0, "n_bytes":2, "reset_id": 9 }, #continous
        "POLARITY": {"id":4, "offset":0x30, "limits": [0,1], "limits_type":1, "n_bytes":2, "reset_id": 10 }, #discrete
        "PORTTUNING": {"id":4, "offset":0x32, "limits": [20,30], "limits_type":1, "n_bytes":2, "reset_id": 11 }, #discrete
        "PRESET1NAME": {"id":8, "offset":0x0, "limits": [""], "limits_type":2, "n_bytes":8, "reset_id": 13 }, #string
        "PRESET2NAME": {"id":9, "offset":0x0, "limits": [""], "limits_type":2, "n_bytes":8, "reset_id": 13 }, #string
        "PRESET3NAME": {"id":0xA,"offset":0x0, "limits": [""], "limits_type":2, "n_bytes":8, "reset_id": 13 }, #string
        "PRESET1LOAD": {"id":0x18, "offset":0x1, "limits": [None], "limits_type":-1, "n_bytes":0, "reset_id": -1 },
        "PRESET2LOAD": {"id":0x19, "offset":0x1, "limits": [None], "limits_type":-1, "n_bytes":0, "reset_id": -1 },
        "PRESET3LOAD": {"id":0x1A, "offset":0x1, "limits": [None], "limits_type":-1, "n_bytes":0, "reset_id": -1 },
        "PRESET4LOAD": {"id":0x1B, "offset":0x1, "limits": [None], "limits_type":-1, "n_bytes":0, "reset_id": -1 },
        "PRESET1SAVE": {"id":0x1C, "offset":0x1, "limits": [None], "limits_type":-1, "n_bytes":0, "reset_id": -1 },
        "PRESET2SAVE": {"id":0x1D, "offset":0x1, "limits": [None], "limits_type":-1, "n_bytes":0, "reset_id": -1 },
        "PRESET3SAVE": {"id":0x1E, "offset":0x1, "limits": [None], "limits_type":-1, "n_bytes":0, "reset_id": -1 }
        #NOTE: 'group' settings can be read at once but not written at once, the sub doesn't support it.
        }

###################    End SB-1000-PRO CONFIG    ###################

###################    Bleak Routines    ###################

VERSION = "v3.52 Final"
RUN_THREAD = True
PARTIAL_FRAME=b''
sync = True

def RX_thread(handle, data):
    #Everything that the svs subwoofer sends to us comes to this callback
    global PARTIAL_FRAME
    global sync
    if data[0] == int.from_bytes(FRAME_PREAMBLE, 'little'):
    #detected a frame start. Start building frame
        if not sync:
        #sync was not reset before, print error and show PREVIOUS wrong frame
            print("ERROR: Frame fragment out of sync received: %s" % (bytes2hexstr(PARTIAL_FRAME)))
        PARTIAL_FRAME = data
    else:
    #detected a frame fragment. Add it to the previous partial frame
        PARTIAL_FRAME = PARTIAL_FRAME + data
    
    decoded_frame = svs_decode(PARTIAL_FRAME)
    sync = decoded_frame["FRAME_RECOGNIZED"]
    if sync:
        if not(len(decoded_frame["VALIDATED_VALUES"]) == 1 and "STANDBY" in decoded_frame["ATTRIBUTES"]):
            print(decoded_frame["VALIDATED_VALUES"])

def start_bt_daemon():
    t1=Thread(target=bleak_device)
    t1.start()

def bleak_device():
    ADDRESS = (SVS_MAC_ADDRESS if platform.system() != "Darwin" else "B9EA5233-37EF-4DD6-87A8-2A875E821C46")
    asyncio.run(TX_thread(ADDRESS, CHAR22))

async def TX_thread(address, char_uuid):
    try:
        async with BleakClient(address,adapter=dev) as client:

            #subscribe to svs parameters characteristic
            await client.start_notify(char_uuid, RX_thread)

            while RUN_THREAD:
            #don't let this method die in order to RX continuously
                for n in range(0,len(TX.BUFFER), 2):
                    await client.write_gatt_char(char_uuid, TX.BUFFER[0])
                    del TX.BUFFER[0:2] #remove frame we just sent from buffer and its metadata
                    await asyncio.sleep(0.2)
                await asyncio.sleep(0.2)
    except:
        traceback.print_exc()
        close_bt_daemon()

def close_bt_daemon():
    global RUN_THREAD
    RUN_THREAD = False
    TX.BUFFER = []
    while True: sys.exit(0)

class TX:
    BUFFER = []
###################    End Bleak Routines    ###################

###################    SVS Frame Routines    ###################

def svs_encode(ftype, param, data=""):
    if ftype == "PRESETLOADSAVE" and SVS_PARAMS[param]["id"] >= 0x18:
    #FRAME FORMAT:
    # PREAMBLE (1 byte) + 
    # 	Frame type (2bytes) + 
    # 		Full frame length (2bytes) +
    # 			ID (4 bytes) +
    # 				Offset to read from/write to (2 bytes) +
    # 					Size to read/write (2 bytes) + 
        frame = SVS_PARAMS[param]["id"].to_bytes(4,"little") + SVS_PARAMS[param]["offset"].to_bytes(2,"little") + SVS_PARAMS[param]["n_bytes"].to_bytes(2,"little")

    elif ftype == "MEMWRITE" and SVS_PARAMS[param]["id"] <= 0xA and SVS_PARAMS[param]["limits_type"] != "group":
    #FRAME FORMAT:
    # PREAMBLE (1 byte) + 
    # 	Frame type (2bytes) + 
    # 		Full frame length (2bytes) +
    # 			ID (4 bytes) +
    # 				Offset to read from/write to (2 bytes) +
    # 					Size to read/write (2 bytes) + 
    # 						Data(0/X bytes) + 
    # 							CRC (2 bytes)
        if type(data) == str and len(data) > 0 and SVS_PARAMS[param]["limits_type"] == 2:
            encoded_data = bytes(data.ljust(SVS_PARAMS[param]["n_bytes"], "\x00"),'utf-8')[:SVS_PARAMS[param]["n_bytes"]]
        elif type(data) in [int, float]:
            if (SVS_PARAMS[param]["limits_type"] == 1 and data in SVS_PARAMS[param]["limits"]) or (SVS_PARAMS[param]["limits_type"] == 0 and max(SVS_PARAMS[param]["limits"]) >= data >= min(SVS_PARAMS[param]["limits"])):
                mask = 0 if data >= 0 else 0xFFFF
                encoded_data = ((int(10 * abs(data)) ^ mask) + (mask % 2)).to_bytes(2, 'little')
            else:
                print("ERROR: Value for %s out of limits" % (param))
                return [b'',""]
        else:
            print("ERROR: Value for %s incorrect" % (param))
            return [b'',""]
        frame = SVS_PARAMS[param]["id"].to_bytes(4,"little") + SVS_PARAMS[param]["offset"].to_bytes(2,"little") + SVS_PARAMS[param]["n_bytes"].to_bytes(2,"little") + encoded_data

    elif ftype == "MEMREAD" and SVS_PARAMS[param]["id"] <= 0xA:
    #FRAME FORMAT:
    # PREAMBLE (1 byte) + 
    # 	Frame type (2bytes) + 
    # 		Full frame length (2bytes) +
    # 			SECT_1 (0/4 bytes) [RESP only] +
    # 				ID (4 bytes) +
    # 					Offset to read from/write to (2 bytes) +
    # 						Size to read/write (2 bytes) + 
    # 							Data(0/X bytes) [RESP only] + 
    # 								PADDING (0/X bytes) [RESP only]
    # 									CRC (2 bytes)
        frame = SVS_PARAMS[param]["id"].to_bytes(4,"little") + SVS_PARAMS[param]["offset"].to_bytes(2,"little") + SVS_PARAMS[param]["n_bytes"].to_bytes(2,"little")

    elif ftype == "RESET" and SVS_PARAMS[param]["id"] <= 0xA:
    #FRAME FORMAT:
    # PREAMBLE (1 byte) + 
    # 	Frame type (2bytes) + 
    # 		Full frame length (2bytes) +
    # 			Reset id (1bytes) +
    # 				CRC (2 bytes)
        frame = SVS_PARAMS[param]["reset_id"].to_bytes(1,"little")

    elif ftype in ["SUB_INFO1", "SUB_INFO2", "SUB_INFO3"]:
    #FRAME FORMAT:
    # PREAMBLE (1 byte) + 
    # 	Frame type (2bytes) + 
    # 		Full frame length (2bytes) +
    #			b'\x00' +
    # 				CRC (2 bytes)
        frame = b'\x00'

    else:
        print("ERROR: Unknown frame type to encode. Can only encode DEV-to-SVS frame types.")
        return [b'',""]

    frame = FRAME_PREAMBLE + SVS_FRAME_TYPES[ftype] + (len(frame) + 7).to_bytes(2,"little") + frame
    frame = frame + crc_hqx(frame,0).to_bytes(2, 'little')
    meta = ftype + " " + str([param]) + " "[:len(str(data))] + str(data)
    return [frame, meta]

def svs_decode(frame):
    O_ATTRIBUTES = []
    O_FTYPE = "UNKNOWN"
    O_FLENGTH =""
    O_SECT_1 = ""
    O_ID = ""
    O_MEM_START = ""
    O_MEM_SIZE = ""
    O_RAW_DATA = b''
    O_B_ENDIAN_DATA = []
    O_VALIDATED_VALUES = {}
    O_RESET_ID = ""
    O_PADDING = ""
    O_CRC = ["0x" + bytes2hexstr(frame[len(frame) - 2:]), "OK" if frame[len(frame)-2:] == crc_hqx(frame[:len(frame)-2],0).to_bytes(2, 'little') else "MISSMATCH"]
    O_FLENGTH = ["0x" + bytes2hexstr(frame[3:5]), int.from_bytes(frame[3:5], 'little'), len(frame)]
    O_RECOGNIZED =  (frame[0] == int.from_bytes(FRAME_PREAMBLE, 'little')) and (O_FLENGTH[1] == O_FLENGTH[2]) and (O_CRC[1] == "OK")
    if O_RECOGNIZED:
        for key in SVS_FRAME_TYPES.keys():
            if SVS_FRAME_TYPES[key] in frame[1:3]:
                O_FTYPE = key
                break;
        O_FTYPE = ["0x" + bytes2hexstr(frame[1:3]), O_FTYPE]

        if O_FTYPE[1] == "PRESETLOADSAVE":
            O_ID = ["0x" + bytes2hexstr(frame[5:9]), int.from_bytes(frame[5:9], 'little')]
            for key in SVS_PARAMS.keys():
                if SVS_PARAMS[key]["id"] == O_ID[1]:
                    O_ID =  O_ID + [key]
                    break;
            O_MEM_START = ["0x" + bytes2hexstr(frame[9:11]),int.from_bytes(frame[9:11], 'little')]
            O_MEM_SIZE = ["0x" + bytes2hexstr(frame[11:13]), int.from_bytes(frame[11:13], 'little')]

        elif O_FTYPE[1] in ["MEMWRITE","MEMREAD","READ_RESP"]:
            ID_position = 9 if O_FTYPE[1] == "READ_RESP" else 5
            O_SECT_1 = ["0x" + bytes2hexstr(frame[5:ID_position]), int.from_bytes(frame[5:ID_position], 'little')] if ID_position > 5 else ""
            O_ID = ["0x" + bytes2hexstr(frame[ID_position:ID_position + 4]), int.from_bytes(frame[ID_position:ID_position + 4], 'little')]
            mem_start = int.from_bytes(frame[ID_position + 4:ID_position + 6], 'little')
            O_MEM_START = ["0x" + bytes2hexstr(frame[ID_position + 4:ID_position + 6]), mem_start]
            mem_size = int.from_bytes(frame[6+ID_position:8+ID_position], 'little')
            O_MEM_SIZE = ["0x" + bytes2hexstr(frame[6 + ID_position:8 + ID_position]), mem_size]
            bytes_left_in_frame = len(frame[8 + ID_position:])

            #read attributes
            for offset in range(0,int(mem_size),2):
                for key in SVS_PARAMS.keys():
                    if SVS_PARAMS[key]["limits_type"] != "group" and SVS_PARAMS[key]["id"] == O_ID[1]:
                        if (mem_start + offset) == SVS_PARAMS[key]["offset"]:
                        #memory position equal to parameter mem address
                            O_ATTRIBUTES.append(key)
                            break;
                        elif (mem_start + offset) >= SVS_PARAMS[key]["offset"] and (mem_start + offset) < (SVS_PARAMS[key]["offset"] + SVS_PARAMS[key]["n_bytes"]):
                        #memory position inside a parameter memory range (memory to memory+size)
                            break;
                        elif (mem_start + offset) < SVS_PARAMS[key]["offset"] or (mem_start + offset) >= (SVS_PARAMS["PORTTUNING"]["offset"] + SVS_PARAMS["PORTTUNING"]["n_bytes"]):
                        #memory position in an undertermined area
                            O_ATTRIBUTES.append("UNKNOWN")
                            break;

            #read datas
            if O_FTYPE[1] != "MEMREAD":
                for attrib in O_ATTRIBUTES:
                    for offset in range(len(O_B_ENDIAN_DATA),len(O_B_ENDIAN_DATA) + int(SVS_PARAMS[attrib]["n_bytes"]/2)):
                        O_B_ENDIAN_DATA.append(int.from_bytes(frame[ID_position + 8 + 2*offset:ID_position + 10 + 2*offset],'little'))
                        O_RAW_DATA = O_RAW_DATA + frame[ID_position + 8 + 2*offset:ID_position + 10 + 2*offset]
                        bytes_left_in_frame = bytes_left_in_frame - 2
                        if attrib != "UNKNOWN":
                           #Validate received values
                            if SVS_PARAMS[attrib]["limits_type"] == 2:
                                value = O_RAW_DATA.decode("utf-8").rstrip('\x00')
                                check = True
                            else:
                                mask = 0 if O_B_ENDIAN_DATA[offset] < 0xf000 else 0xFFFF
                                value = ((-1)**(mask % 2)) * ((O_B_ENDIAN_DATA[offset] - (mask % 2)) ^ mask)/10
                                if SVS_PARAMS[attrib]["limits_type"] == 1:
                                    check = value in SVS_PARAMS[attrib]["limits"]
                                elif SVS_PARAMS[attrib]["limits_type"] == 0:
                                    check = max(SVS_PARAMS[attrib]["limits"]) >= value >= min(SVS_PARAMS[attrib]["limits"]) 
                            if check:
                                O_VALIDATED_VALUES[attrib] = int(value) if ".0" in str(value) else value
            #read PADDING
            O_PADDING = "0x" + bytes2hexstr(frame[len(frame) - bytes_left_in_frame:len(frame)-2]) if(len(bytes2hexstr(frame[len(frame) - bytes_left_in_frame:len(frame)-2])) > 0) else ""

        elif O_FTYPE[1] == "RESET":
            O_RESET_ID = ["0x" + bytes2hexstr(frame[5:6]), "UNKNOWN"]
            for key in SVS_PARAMS.keys():
                if SVS_PARAMS[key]["reset_id"] == frame[5]:
                    O_RESET_ID[1] = key
                    break;

        elif "SUB_INFO" in O_FTYPE[1]:
            next_data = 5
            if "RESP" in O_FTYPE[1]:
                O_SECT_1 = ["0x" + bytes2hexstr(frame[next_data:next_data+4]), int.from_bytes(frame[next_data:next_data+4], 'little')]
                next_data = next_data + 4
                O_ATTRIBUTES.append(O_FTYPE[1].split("_")[1])
                if "1" in O_FTYPE[1]:
                    O_VALIDATED_VALUES["DUMP"] = [{"CONTROL_SEQUENCE":[bytes2hexstr(frame[next_data+1:next_data+1+frame[next_data]]),hex(frame[next_data+1+frame[next_data]])]}, {"PARAM_DUMP": bytes2hexstr(frame[next_data + 2 + frame[next_data]:next_data + frame[next_data] + 44])}]
                    next_data = next_data + frame[next_data] + 44
                elif "2" in O_FTYPE[1]:
                    O_VALIDATED_VALUES["SW_VERSION"] = frame[next_data+1:next_data+1+frame[next_data]].decode('utf-8')
                    next_data = next_data+1+frame[next_data]
                elif "3" in O_FTYPE[1]:
                    O_VALIDATED_VALUES["HW_VERSION"] = frame[next_data+1:next_data+1+frame[next_data]].decode('utf-8')
                    next_data = next_data+1+frame[next_data]
            O_PADDING = "0x" + bytes2hexstr(frame[next_data:len(frame)-2]) if len(frame[next_data:len(frame)-2]) > 0 else ""

    output = {}
    for key,val in [("ATTRIBUTES",O_ATTRIBUTES), ("FRAME_RECOGNIZED",O_RECOGNIZED), ("PREAMBLE",str(hex(frame[0]))), ("FRAME_TYPE",O_FTYPE), ("FRAME_LENGTH", O_FLENGTH), ("SECT_1", O_SECT_1), ("ID", O_ID), ("RESET_ID", O_RESET_ID) , ("MEMORY_START", O_MEM_START), ("DATA_LENGTH", O_MEM_SIZE), ("DATA", ["0x" + bytes2hexstr(O_RAW_DATA), O_RAW_DATA, O_B_ENDIAN_DATA] if len(bytes2hexstr(O_RAW_DATA)) > 0 else ""), ("VALIDATED_VALUES", O_VALIDATED_VALUES), ("PADDING", O_PADDING), ("CRC",O_CRC)]:
        if type(val) == bool or len(val) > 0:
            output[key] = val
    return output

def bytes2hexstr(bytes_input):
    return hexlify(bytes_input).decode("utf-8")
    
###################    End SVS Frame Routines    ###################

###################    main()    ###################

def show_usage():
    print('\npySVS ' + VERSION + '. Read and set SVS SB1000P Subwoofer values. By Logon84 http://github.com/logon84')
    print('USAGE: pySVS.py <MAC_Address> <-b device> <parameter1> <value1> <parameter2> <value2> etc...')
    print('Note: MAC address is required as first positional arguement.')
    print('\n-b dev or --btiface=dev: Specify a different BT interface to use (default is hci0).')
    print('-h or --help: Show this help.')
    print('-v or --version: Show program version.')
    print('-e or --encode: Just print built frames based on param values.')
    print('-d FRAME or --decode=FRAME: Decode values of a frame.')
    print('-i or --info: Show subwoofer info.')
    print('-s ftype@param@data or --send ftype@param@data: Send svs_encode frame type, param and data (-s help).')
    print('\nPARAMETER LIST:')
    print('\t-l X@Y@Z or --lpf=X@Y@Z: Sets Low Pass Filter to X[0(OFF),1(ON)], Y[freq] and Z[slope].')
    print('\t-q V@W@X@Y@Z or --peq=V@W@X@Y@Z: Sets PEQ V[1..3], W[0(OFF),1(ON)], X[freq], Y[boost] and Z[Qfactor].')
    print('\t-r X@Y@Z or --roomgain=X@Y@Z: Sets RoomGain X[0(OFF),1(ON)], Y[freq] and Z[slope].')
    print('\t-o X or --volume=X: Sets volume level to X on subwoofer.')
    print('\t-f X or --phase=X: Sets phase level to X on subwoofer.')
    print('\t-k X or --polarity=X: Sets polarity to 0(+) or 1(-) on subwoofer.')
    print('\t-p X or --preset=X: Load preset X[1..4(FACTORY DEFAULT PRESET)] on subwoofer.')
    print('\tTo ask subwoofer for one or more values, set parameter value to \"A\"sk.\n')
    return

def multibinder(widget, function):
    for event in ["<ButtonRelease-1>", "<ButtonRelease-2>", "<KeyRelease-Left>", "<KeyRelease-Right>"]:
        widget.bind(event, function)
    return

def string_isalnumify(in_string):
    return ''.join([char for char in in_string.upper() if char.isalnum()])

def main():
    global dev
    dev="hci0"
    built_frames = []
    encode=0
    try:
        options, arguments = getopt.getopt(sys.argv[2:],"b:hved:is:l:q:r:o:f:k:p:",["btiface=","help","version","encode","decode=","info", "send=","lpf=","peq=","roomgain=","volume=", "phase=", "polarity=", "preset="])
    except getopt.GetoptError as err:
        show_usage()
        print("ERROR: " + str(err) + "\n")
        sys.exit(2)

    # mac address is required as first positional arguement
    global SVS_MAC_ADDRESS
    mac_in = sys.argv[1]
    if len(mac_in.replace("-",":").split(":")) == 6 and len(mac_in) == 17: 
        SVS_MAC_ADDRESS = mac_in.replace("-",":")
    else:
        print("Valid MAC address must be provided as first positional arguement")
        sys.exit(1)

    for opt, opt_val in options:
        if opt in ("-h", "--help"):
            show_usage()
            sys.exit(0)
        elif opt in ("-v", "--version"):
            print(VERSION)
            sys.exit(0)
        elif opt in ("-b", "--btiface"):
            dev=opt_val
        elif opt in ("-e", "--encode"):
            encode=1
        elif opt in ("-d", "--decode"):
            print(svs_decode(unhexlify(opt_val.replace("0x",""))))
            sys.exit(0)
        elif opt in ("-i", "--info"):
            built_frames += svs_encode("SUB_INFO1", "") + svs_encode("SUB_INFO2", "") + svs_encode("SUB_INFO3", "")
        elif opt in ("-s", "--send"):
            if opt_val == "help" or len(opt_val.split("@")) !=3:
                print("FRAME_TYPE@PARAMETER@DATA\n\nAvailable frame types: " + ", ".join(key for key in SVS_FRAME_TYPES.keys() if "RESP" not in key) + "\n\n" + "Available frame parameters: " + ", ".join(key for key in SVS_PARAMS.keys()) + "\n" )
                sys.exit(0)
            data = opt_val.split("@",2)[2]
            if len(data) > 0:
                data = string_isalnumify(data) if SVS_PARAMS[opt_val.split("@")[1].upper()]["limits_type"] == 2 else float(data)
                data = int(data) if type(SVS_PARAMS[opt_val.split("@")[1].upper()]["limits"][0]) == int else data
            built_frames += svs_encode(opt_val.split("@")[0].upper(), opt_val.split("@")[1].upper(), data)
        elif opt in ("-l", "--lpf"):
            if len(opt_val.split("@")) == 3:
                sub_params = ["LOW_PASS_FILTER_ENABLE","LOW_PASS_FILTER_FREQ","LOW_PASS_FILTER_SLOPE"]
                for i in range(0,3):
                    if len(opt_val.split("@")[i]) > 0:
                        built_frames += svs_encode("MEMREAD", sub_params[i]) if opt_val.split("@")[i].upper() == 'A' else svs_encode("MEMWRITE", sub_params[i], int(float(opt_val.split("@")[i])))
            else:
                print("ERROR: Values for LPF incorrect\nExamples of correct values: 1@@12, 0@50@12, A@@6")
                sys.exit(1)
        elif opt in ("-q", "--peq"):
            if len(opt_val.split("@")) == 5:
                peq_number = opt_val.split("@")[0]
                if int(peq_number) in range(1,4):
                    sub_params = ["PEQ" + peq_number + "_ENABLE","PEQ" + peq_number + "_FREQ","PEQ" + peq_number + "_BOOST","PEQ" + peq_number + "_QFACTOR"]
                    for i in range(1,5):
                        if len(opt_val.split("@")[i]) > 0:
                            built_frames += svs_encode("MEMREAD",sub_params[i-1]) if opt_val.split("@")[i].upper() == 'A' else svs_encode("MEMWRITE",sub_params[i-1],float(opt_val.split("@")[i]))
                else:
                    print("ERROR: PEQ profile number incorrect")
                    sys.exit(1)
            else:
                print("ERROR: Values for PEQ incorrect\nExamples of correct values: 2@1@@@0.2, 3@0@40@-11.5@10, 1@A@@@")
                sys.exit(2)
        elif opt in ("-r", "--roomgain"):
            if len(opt_val.split("@")) == 3:
                sub_params = ["ROOM_GAIN_ENABLE","ROOM_GAIN_FREQ","ROOM_GAIN_SLOPE"]
                for i in range(0,3):
                    if len(opt_val.split("@")[i]) > 0:
                        built_frames += svs_encode("MEMREAD",sub_params[i]) if opt_val.split("@")[i].upper() == 'A' else svs_encode("MEMWRITE",sub_params[i],int(float(opt_val.split("@")[i])))
            else:
                print("ERROR: Values for Roomgain incorrect\nExamples of correct values: 1@@12, 0@31@12, A@@6")
                sys.exit(1)
        elif opt in ("-o", "--volume"):
            built_frames += svs_encode("MEMREAD", "VOLUME") if opt_val.upper() == 'A' else svs_encode("MEMWRITE", "VOLUME", int(float(opt_val)))
        elif opt in ("-f", "--phase"):
            built_frames += svs_encode("MEMREAD", "PHASE") if opt_val.upper() == 'A' else svs_encode("MEMWRITE", "PHASE", int(float(opt_val)))
        elif opt in ("-k", "--polarity"):
            built_frames += svs_encode("MEMREAD", "POLARITY") if opt_val.upper() == 'A' else svs_encode("MEMWRITE", "POLARITY", int(float(opt_val)))
        elif opt in ("-p", "--preset"):
            if int(opt_val) in range (1,5): 
                built_frames += svs_encode("PRESETLOADSAVE","PRESET" + opt_val + "LOAD")
            else:
                print("ERROR: Incorrect preset number specified")

    try:
        operands = [int(arg) for arg in arguments]
    except ValueError:
        show_usage()
        sys.exit(2)
        raise SystemExit()

    if len(built_frames) > 0:
        if encode:
            for i in range(0,len(built_frames),2):
                print(bytes2hexstr(built_frames[i]))
            sys.exit(0)
        else:
            start_bt_daemon()
            TX.BUFFER=built_frames
            while len(TX.BUFFER) > 0: pass
            time.sleep(0.5)
            close_bt_daemon()
    else:
        print("Nothing to do!")
        sys.exit(0)

if __name__ == "__main__":
    sys.exit(main())
###################    End main()    ###################
