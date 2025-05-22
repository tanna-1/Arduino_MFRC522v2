/* SPDX-License-Identifier: LGPL-2.1 */
#pragma once

#include <Arduino.h>
#include <MFRC522v2.h>
#include <MFRC522Driver.h>
#include <MFRC522Debug.h>

class MFRC522TCL
{
private:
  using StatusCode = MFRC522Constants::StatusCode;
  using PICC_Command = MFRC522Constants::PICC_Command;
  using PCD_Register = MFRC522Constants::PCD_Register;
  using PCD_Command = MFRC522Constants::PCD_Command;

  MFRC522 &_device;
  MFRC522Driver &_driver;
  bool _logErrors;
  Print *_logPrint; // Injected Arduino API could be replaced by void* if required.

public:
  MFRC522TCL(MFRC522 &device, const bool logErrors, Print *logPrint = nullptr)
      : _device(device), _driver(device._driver), _logPrint(logPrint)
  {
    _logErrors = logErrors && (logPrint != nullptr);
  };

  // ISO/IEC 14443-4 bit rates
  enum TagBitRates : byte
  {
    BITRATE_106KBITS = 0x00,
    BITRATE_212KBITS = 0x01,
    BITRATE_424KBITS = 0x02,
    BITRATE_848KBITS = 0x03
  };

  // Structure to store ISO/IEC 14443-4 ATS
  typedef struct
  {
    byte size;
    uint16_t fsc; // Frame size for proximity card

    struct
    {
      bool transmitted;
      bool sameD;     // Only the same D for both directions supported
      TagBitRates ds; // Send D
      TagBitRates dr; // Receive D
    } ta1;

    struct
    {
      bool transmitted;
      byte fwi;  // Frame waiting time integer
      byte sfgi; // Start-up frame guard time integer
    } tb1;

    struct
    {
      bool transmitted;
      bool supportsCID;
      bool supportsNAD;
    } tc1;

    // Raw data from ATS
    // ATS cannot be bigger than FSD - 2 bytes (CRC), according to ISO 14443-4 5.2.2
    byte data[MFRC522::FIFO_SIZE - 2];
  } Ats;

  // A struct used for passing PCB Block
  typedef struct
  {
    struct
    {
      byte pcb;
      byte cid;
      byte nad;
    } prologue;
    struct
    {
      byte size;
      byte *data;
    } inf;
  } PcbBlock;

  /////////////////////////////////////////////////////////////////////////////////////
  // Functions for communicating with ISO/IEC 14443-4 cards
  /////////////////////////////////////////////////////////////////////////////////////
  bool PICC_IsTCLPresent();
  StatusCode PICC_TCL_Select();
  StatusCode PICC_RequestATS(Ats *ats);
  StatusCode PICC_PPS(TagBitRates sendBitRate, TagBitRates receiveBitRate);
  StatusCode TCL_Transceive(PcbBlock *send, PcbBlock *back);
  StatusCode TCL_Transceive(byte *sendData, byte sendLen, byte *backData = NULL, byte *backLen = NULL);
  StatusCode TCL_TransceiveRBlock(bool ack, byte *backData = NULL, byte *backLen = NULL, bool *finalBlock = NULL);
  StatusCode TCL_Deselect();

private:
  StatusCode PCD_TransceiveDataEx(byte *sendData, byte sendLen,
                                  byte *backData, byte *backLen,
                                  byte *validBits = nullptr, byte rxAlign = 0,
                                  bool checkCRC = false,
                                  bool waitForData = true,
                                  unsigned long timeoutMs = 500);

  Ats ats = {0};
  bool blockToggle = false;
};
