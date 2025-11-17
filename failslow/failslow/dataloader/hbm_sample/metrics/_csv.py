from typing import List, Tuple, Union, Dict
from csv import DictWriter, writer
import datetime
import os
import logging

DELIM = ","

logger = logging.getLogger(__name__)

def write_to_csv(dir_path: str, 
                 records: Union[List[Tuple], List[Dict]],
                 headers: List[str]):
    
    if not os.path.exists(dir_path):
        os.makedirs(dir_path, mode=0o777, exist_ok=True)
    
    if len(records) == 0:
        logger.debug("No records to write to csv..., if you have enabled csv dump, "
                     "then you might have a problem.")
        return
    is_dict = False
    if isinstance(records[0], dict):
        is_dict = True
        headers = records[0].keys()
    
    # write a file per unique hour
    current_datetime = datetime.datetime.utcnow()
    
    file_name = f"{current_datetime.year}-{current_datetime.month}-{current_datetime.day}-{current_datetime.hour}.csv"
    file_path = os.path.join(dir_path, file_name)
    
    if not os.path.exists(file_path):
        with open(file_path, "w") as f:
            dw = DictWriter(f, fieldnames=headers, delimiter=DELIM)
            dw.writeheader()
    
    if is_dict:
        with open(file_path, "a") as f:
            # write the dict into the csv
            dw = DictWriter(f, fieldnames=headers, delimiter=DELIM)
            dw.writerows(records)
    else:
        with open(file_path, "a") as f:
            # write the tuple into the csv
            w = writer(f, delimiter=DELIM)
            w.writerows(records)
        
