import secrets
import logging

from shellerate import strings
 

def has_restricted_chars(string, r_chars=[]):
  for i in r_chars:
    if i in string:
      return True
  return false



def bit_not(n, bits=8):
  return (1<<bits-1) - 1 - n

