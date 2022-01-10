import numpy as np
import pandas as pd
import math
import re
#import enchant
import pickle
from collections import Counter
#import swifter

with open('../Datasets/char_freq.pkl', 'rb') as f:
    char_freq = pickle.load(f)

def remove_tlds(domain):
    words=domain.split(".")
    return words[-3]

def length(domain):
    return len(domain)

def get_freq(domains):
    char_freq={}
    tot=0
    for i in range(len(domains)):
        count=Counter(domains[i])
        for key in count:
            if key not in char_freq:
                char_freq[key]=0
            char_freq[key]+=count[key]
            tot+=count[key]

    len(char_freq)
    
    for key in char_freq:
        char_freq[key]=(char_freq[key]/tot)
        
    return char_freq

def relative_entropy(data, base):
    entropy = 0.0
    length = len(data) * 1.0
    
    if length > 0:
        cnt= Counter(data)
        
    for char, count in cnt.items():
        observed = count / length
        expected = base[char]
        entropy += observed * math.log((observed / expected),2)
        
    return entropy

def count_num(domain):
    cnt=0
    for let in domain:
        if let.isnumeric():
            cnt=cnt+1
    
    return cnt/len(domain)

def max_consecutive_consonants(domain):
    consonant_list = re.findall(r'[bcdfghjklmnpqrstvwxyz]+', domain , re.IGNORECASE)
    if len(consonant_list) > 0:
        return len(max(consonant_list, key=len))
    else:
        return 0
    
def max_consecutive_vowels(domain):
    vowel_list = re.findall(r'[aeiou]+', domain , re.IGNORECASE)
    if len(vowel_list) > 0:
        return len(max(vowel_list, key=len))
    else:
        return 0
    
def vowel_count(domain):
    return len(re.findall(r'[aeiou]', domain , re.IGNORECASE))

def vowel_rate(domain):
    return len(re.findall(r'[aeiou]', domain , re.IGNORECASE))/len(domain)

def create_feature_vector(domain):
    feature_vector = []
    feature_vector.append(length(domain))
    feature_vector.append(relative_entropy(domain, char_freq))
    feature_vector.append(count_num(domain))
    feature_vector.append(max_consecutive_consonants(domain))
    feature_vector.append(max_consecutive_vowels(domain))
    feature_vector.append(vowel_count(domain))
    feature_vector.append(vowel_rate(domain))
    
    return feature_vector