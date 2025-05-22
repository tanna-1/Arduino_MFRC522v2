#include "MFRC522TCL.h"

/**
 * Executes the Transceive command.
 * CRC validation can only be done if backData and backLen are specified.
 * 
 * @return StatusCode::STATUS_OK on success, StatusCode::STATUS_??? otherwise.
 */
MFRC522::StatusCode MFRC522TCL::PCD_TransceiveDataEx(byte *sendData,        ///< Pointer to the data to transfer to the FIFO.
                                                    byte sendLen,           ///< Number of bytes to transfer to the FIFO.
                                                    byte *backData,         ///< nullptr or pointer to buffer if data should be read back after executing the command.
                                                    byte *backLen,          ///< In: Max number of bytes to write to *backData. Out: The number of bytes returned.
                                                    byte *validBits,        ///< In/Out: The number of valid bits in the last byte. 0 for 8 valid bits. Default nullptr.
                                                    byte rxAlign,           ///< In: Defines the bit position in backData[0] for the first bit received. Default 0.
                                                    bool checkCRC,          ///< In: True => The last two bytes of the response is assumed to be a CRC_A that must be validated.
                                                    bool waitForData,       ///< In: True => Wait for data in FIFO buffer. Zero length responses will timeout.
                                                    unsigned long timeoutMs ///< In: Timeout in milliseconds.
                                                    ) {
  // Prepare values for BitFramingReg
  byte txLastBits = validBits ? *validBits : 0;
  byte bitFraming = (rxAlign << 4)+txLastBits;    // RxAlign = BitFramingReg[6..4]. TxLastBits = BitFramingReg[2..0]

  _driver.PCD_WriteRegister(PCD_Register::CommandReg, PCD_Command::PCD_Idle);      // Stop any active command.
  _driver.PCD_WriteRegister(PCD_Register::ComIrqReg, 0x7F);          // Clear all seven interrupt request bits
  _driver.PCD_WriteRegister(PCD_Register::FIFOLevelReg, 0x80);        // FlushBuffer = 1, FIFO initialization
  _driver.PCD_WriteRegister(PCD_Register::FIFODataReg, sendLen, sendData);  // Write sendData to the FIFO
  _driver.PCD_WriteRegister(PCD_Register::BitFramingReg, bitFraming);    // Bit adjustments
  _driver.PCD_WriteRegister(PCD_Register::CommandReg, PCD_Command::PCD_Transceive); // Execute the command
  _device.PCD_SetRegisterBitMask(PCD_Register::BitFramingReg, 0x80);  // StartSend=1, transmission of data starts
  
  // Wait for the command to complete.
  // In PCD_Init() we set the TAuto flag in TModeReg. This means the timer automatically starts when the PCD stops transmitting.
  const auto deadline = millis() + timeoutMs;
  bool completed = false;
  
  do {
    byte n = _driver.PCD_ReadRegister(PCD_Register::ComIrqReg);  // ComIrqReg[7..0] bits are: Set1 TxIRq RxIRq IdleIRq HiAlertIRq LoAlertIRq ErrIRq TimerIRq
    
    // RxIRq set and FIFO has data or don't wait for data
    if(n & 0x20 && (!waitForData || _driver.PCD_ReadRegister(PCD_Register::FIFOLevelReg) > 0)) {
      completed = true;
      break;
    }
    yield();
  }
  while (millis() < deadline);
  
  if(!completed) {
    return StatusCode::STATUS_TIMEOUT;
  }
  
  // Stop now if any errors except collisions were detected.
  byte errorRegValue = _driver.PCD_ReadRegister(PCD_Register::ErrorReg); // ErrorReg[7..0] bits are: WrErr TempErr reserved BufferOvfl CollErr CRCErr ParityErr ProtocolErr
  if(errorRegValue & 0x13) {   // BufferOvfl ParityErr ProtocolErr
    return StatusCode::STATUS_ERROR;
  }
  
  byte _validBits = 0;
  
  // If the caller wants data back, get it from the MFRC522.
  if(backData && backLen) {
    byte n = _driver.PCD_ReadRegister(PCD_Register::FIFOLevelReg);  // Number of bytes in the FIFO
    if(n > *backLen) {
      return StatusCode::STATUS_NO_ROOM;
    }
    *backLen = n;                      // Number of bytes returned
    _driver.PCD_ReadRegister(PCD_Register::FIFODataReg, n, backData, rxAlign);  // Get received data from FIFO
    _validBits = _driver.PCD_ReadRegister(PCD_Register::ControlReg) & 0x07;    // RxLastBits[2:0] indicates the number of valid bits in the last received byte. If this value is 000b, the whole byte is valid.
    if(validBits) {
      *validBits = _validBits;
    }
  }
  
  // Tell about collisions
  if(errorRegValue & 0x08) {    // CollErr
    return StatusCode::STATUS_COLLISION;
  }
  
  // Perform CRC_A validation if requested.
  if(backData && backLen && checkCRC) {
    // In this case a MIFARE Classic NAK is not OK.
    if(*backLen == 1 && _validBits == 4) {
      return StatusCode::STATUS_MIFARE_NACK;
    }
    // We need at least the CRC_A value and all 8 bits of the last byte must be received.
    if(*backLen < 2 || _validBits != 0) {
      return StatusCode::STATUS_CRC_WRONG;
    }
    // Verify CRC_A - do our own calculation and store the control in controlBuffer.
    byte                controlBuffer[2];
    MFRC522::StatusCode status = _device.PCD_CalculateCRC(&backData[0], *backLen-2, &controlBuffer[0]);
    if(status != StatusCode::STATUS_OK) {
      return status;
    }
    if((backData[*backLen-2] != controlBuffer[0]) || (backData[*backLen-1] != controlBuffer[1])) {
      return StatusCode::STATUS_CRC_WRONG;
    }
  }
  
  return StatusCode::STATUS_OK;
}

bool MFRC522TCL::PICC_IsTCLPresent()
{
  // IF SAK bit 6 = 1 then it is ISO/IEC 14443-4 (T=CL)
  // A Request ATS command should be sent
  // We also check SAK bit 3 is cero, as it stands for UID complete (1
  // would tell us it is incomplete)
  return (_device.uid.sak & 0x24) == 0x20;
}

MFRC522::StatusCode MFRC522TCL::PICC_TCL_Select()
{
  auto result = PICC_RequestATS(&ats);
  if (result != StatusCode::STATUS_OK)
  {
    return result;
  }

  if (ats.size == 0)
  {
    return StatusCode::STATUS_ERROR;
  }

  // TA1 has been transmitted?
  // PPS must be supported...
  if (ats.ta1.transmitted)
  {
    // TA1
    //  8 | 7 | 6 | 5 | 4 | 3 | 2 | 1 | Description
    // ---+---+---+---+---+---+---+---+------------------------------------------
    //  0 | - | - | - | 0 | - | - | - | Different D for each direction supported
    //  1 | - | - | - | 0 | - | - | - | Only same D for both direction supported
    //  - | x | x | x | 0 | - | - | - | DS (Send D)
    //  - | - | - | - | 0 | x | x | x | DR (Receive D)
    //
    // D to bitrate table
    //  3 | 2 | 1 | Value
    // ---+---+---+-----------------------------
    //  1 | - | - | 848 kBaud is supported
    //  - | 1 | - | 424 kBaud is supported
    //  - | - | 1 | 212 kBaud is supported
    //  0 | 0 | 0 | Only 106 kBaud is supported
    //
    // Note: 106 kBaud is always supported
    //
    // I have almost constant timeouts when changing speeds :(
    // default never used, so only delarate
    // TagBitRates ds = BITRATE_106KBITS;
    // TagBitRates dr = BITRATE_106KBITS;
    TagBitRates ds;
    TagBitRates dr;

    //// TODO Not working at 848 or 424
    // if (ats.ta1.ds & 0x04)
    //{
    //	ds = BITRATE_848KBITS;
    // }
    // else if (ats.ta1.ds & 0x02)
    //{
    //	ds = BITRATE_424KBITS;
    // }
    // else if (ats.ta1.ds & 0x01)
    //{
    //	ds = BITRATE_212KBITS;
    // }
    // else
    //{
    //	ds = BITRATE_106KBITS;
    // }

    if (ats.ta1.ds & 0x01)
    {
      ds = BITRATE_212KBITS;
    }
    else
    {
      ds = BITRATE_106KBITS;
    }

    //// Not working at 848 or 424
    // if (ats.ta1.dr & 0x04)
    //{
    //	dr = BITRATE_848KBITS;
    // }
    // else if (ats.ta1.dr & 0x02)
    //{
    //	dr = BITRATE_424KBITS;
    // }
    // else if (ats.ta1.dr & 0x01)
    //{
    //	dr = BITRATE_212KBITS;
    // }
    // else
    //{
    //	dr = BITRATE_106KBITS;
    // }

    if (ats.ta1.dr & 0x01)
    {
      dr = BITRATE_212KBITS;
    }
    else
    {
      dr = BITRATE_106KBITS;
    }

    result = PICC_PPS(ds, dr);
  }

  return result;
}

/**
 * Transmits a Request command for Answer To Select (ATS).
 *
 * @return StatusCode::STATUS_OK on success, StatusCode::STATUS_??? otherwise.
 */
MFRC522::StatusCode MFRC522TCL::PICC_RequestATS(Ats *ats)
{
  // TODO unused variable
  // byte count;
  MFRC522::StatusCode result;

  byte bufferATS[MFRC522::FIFO_SIZE];
  byte bufferSize = sizeof(bufferATS);

  memset(bufferATS, 0, sizeof(bufferATS));

  // Build command buffer
  bufferATS[0] = PICC_Command::PICC_CMD_RATS;

  // The CID defines the logical number of the addressed card and has a range of 0
  // through 14; 15 is reserved for future use (RFU).
  //
  // FSDI codes the maximum frame size (FSD) that the terminal can receive.
  //
  // FSDI        |  0  |  1  |  2  |  3  |  4  |  5  |  6  |  7  |  8  |  9-F
  // ------------+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----------
  // FSD (bytes) |  16 |  24 |  32 |  40 |  48 |  64 |  96 | 128 | 256 | RFU > 256
  //
  bufferATS[1] = 0x50; // FSD=64, CID=0

  // Calculate CRC_A
  result = _device.PCD_CalculateCRC(bufferATS, 2, &bufferATS[2]);
  if (result != StatusCode::STATUS_OK)
  {
    return result;
  }

  // Transmit the buffer and receive the response, validate CRC_A.
  result = PCD_TransceiveDataEx(bufferATS, 4, bufferATS, &bufferSize, NULL, 0, true);
  if (result != StatusCode::STATUS_OK)
  {
    _device.PICC_HaltA();
  }

  // Set the ats structure data
  ats->size = bufferATS[0];

  // T0 byte:
  //
  // b8 | b7 | b6 | b5 | b4 | b3 | b2 | b1 | Meaning
  //----+----+----+----+----+----+----+----+---------------------------
  //  0 | ...| ...| ...| ...|... | ...| ...| Set to 0 (RFU)
  //  0 |  1 | x  |  x | ...|... | ...| ...| TC1 transmitted
  //  0 |  x | 1  |  x | ...|... | ...| ...| TB1 transmitted
  //  0 |  x | x  |  1 | ...|... | ...| ...| TA1 transmitted
  //  0 | ...| ...| ...|  x |  x |  x | x  | Maximum frame size (FSCI)
  //
  // FSCI        |  0  |  1  |  2  |  3  |  4  |  5  |  6  |  7  |  8  |  9-F
  // ------------+-----+-----+-----+-----+-----+-----+-----+-----+-----+-----------
  // FSC (bytes) |  16 |  24 |  32 |  40 |  48 |  64 |  96 | 128 | 256 | RFU > 256
  //
  // Default FSCI is 2 (32 bytes)
  if (ats->size > 0x01)
  {
    // TC1, TB1 and TA1 where NOT transmitted
    ats->ta1.transmitted = (bool)(bufferATS[1] & 0x40);
    ats->tb1.transmitted = (bool)(bufferATS[1] & 0x20);
    ats->tc1.transmitted = (bool)(bufferATS[1] & 0x10);

    // Decode FSCI
    switch (bufferATS[1] & 0x0F)
    {
    case 0x00:
      ats->fsc = 16;
      break;
    case 0x01:
      ats->fsc = 24;
      break;
    case 0x02:
      ats->fsc = 32;
      break;
    case 0x03:
      ats->fsc = 40;
      break;
    case 0x04:
      ats->fsc = 48;
      break;
    case 0x05:
      ats->fsc = 64;
      break;
    case 0x06:
      ats->fsc = 96;
      break;
    case 0x07:
      ats->fsc = 128;
      break;
    case 0x08:
      ats->fsc = 256;
      break;
      // TODO: What to do with RFU (Reserved for future use)?
    default:
      break;
    }

    // TA1
    if (ats->ta1.transmitted)
    {
      ats->ta1.sameD = (bool)(bufferATS[2] & 0x80);
      ats->ta1.ds = (TagBitRates)((bufferATS[2] & 0x70) >> 4);
      ats->ta1.dr = (TagBitRates)(bufferATS[2] & 0x07);
    }
    else
    {
      // Default TA1
      ats->ta1.ds = BITRATE_106KBITS;
      ats->ta1.dr = BITRATE_106KBITS;
    }

    // TB1
    if (ats->tb1.transmitted)
    {
      uint8_t tb1Index = 2;

      if (ats->ta1.transmitted)
        tb1Index++;

      ats->tb1.fwi = (bufferATS[tb1Index] & 0xF0) >> 4;
      ats->tb1.sfgi = bufferATS[tb1Index] & 0x0F;
    }
    else
    {
      // Defaults for TB1
      ats->tb1.fwi = 0;  // TODO: Don't know the default for this!
      ats->tb1.sfgi = 0; // The default value of SFGI is 0 (meaning that the card does not need any particular SFGT)
    }

    // TC1
    if (ats->tc1.transmitted)
    {
      uint8_t tc1Index = 2;

      if (ats->ta1.transmitted)
        tc1Index++;
      if (ats->tb1.transmitted)
        tc1Index++;

      ats->tc1.supportsCID = (bool)(bufferATS[tc1Index] & 0x02);
      ats->tc1.supportsNAD = (bool)(bufferATS[tc1Index] & 0x01);
    }
    else
    {
      // Defaults for TC1
      ats->tc1.supportsCID = true;
      ats->tc1.supportsNAD = false;
    }
  }
  else
  {
    // TC1, TB1 and TA1 where NOT transmitted
    ats->ta1.transmitted = false;
    ats->tb1.transmitted = false;
    ats->tc1.transmitted = false;

    // Default FSCI
    ats->fsc = 32; // Defaults to FSCI 2 (32 bytes)

    // Default TA1
    ats->ta1.sameD = false;
    ats->ta1.ds = BITRATE_106KBITS;
    ats->ta1.dr = BITRATE_106KBITS;

    // Defaults for TB1
    ats->tb1.transmitted = false;
    ats->tb1.fwi = 0;  // TODO: Don't know the default for this!
    ats->tb1.sfgi = 0; // The default value of SFGI is 0 (meaning that the card does not need any particular SFGT)

    // Defaults for TC1
    ats->tc1.transmitted = false;
    ats->tc1.supportsCID = true;
    ats->tc1.supportsNAD = false;
  }

  memcpy(ats->data, bufferATS, bufferSize - 2);

  // Reset block toggle
  blockToggle = false;

  return result;
} // End PICC_RequestATS()

/**
 * Transmits Protocol and Parameter Selection Request (PPS)
 *
 * @return StatusCode::STATUS_OK on success, StatusCode::STATUS_??? otherwise.
 */
MFRC522::StatusCode MFRC522TCL::PICC_PPS(TagBitRates sendBitRate,   ///< DS
                                         TagBitRates receiveBitRate ///< DR
)
{
  StatusCode result;

  // TODO not used
  // byte txReg = _driver.PCD_ReadRegister(PCD_Register::TxModeReg) & 0x8F;
  // byte rxReg = _driver.PCD_ReadRegister(PCD_Register::RxModeReg) & 0x8F;

  byte ppsBuffer[5];
  byte ppsBufferSize = 5;
  // Start byte: The start byte (PPS) consists of two parts:
  //  –The upper nibble(b8–b5) is set to’D'to identify the PPS. All other values are RFU.
  //  -The lower nibble(b4–b1), which is called the ‘card identifier’ (CID), defines the logical number of the addressed card.
  ppsBuffer[0] = 0xD0; // CID is hardcoded as 0 in RATS
  ppsBuffer[1] = 0x11; // PPS0 indicates whether PPS1 is present

  // Bit 8 - Set to '0' as MFRC522 allows different bit rates for send and receive
  // Bit 4 - Set to '0' as it is Reserved for future use.
  // ppsBuffer[2] = (((sendBitRate & 0x03) << 4) | (receiveBitRate & 0x03)) & 0xE7;
  ppsBuffer[2] = (((sendBitRate & 0x03) << 2) | (receiveBitRate & 0x03)) & 0xE7;

  // Calculate CRC_A
  result = _device.PCD_CalculateCRC(ppsBuffer, 3, &ppsBuffer[3]);
  if (result != StatusCode::STATUS_OK)
  {
    return result;
  }

  // Transmit the buffer and receive the response, validate CRC_A.
  result = PCD_TransceiveDataEx(ppsBuffer, 5, ppsBuffer, &ppsBufferSize, NULL, 0, true);
  if (result == StatusCode::STATUS_OK)
  {
    // Make sure it is an answer to our PPS
    // We should receive our PPS byte and 2 CRC bytes
    if ((ppsBufferSize == 3) && (ppsBuffer[0] == 0xD0))
    {
      byte txReg = _driver.PCD_ReadRegister(PCD_Register::TxModeReg) & 0x8F;
      byte rxReg = _driver.PCD_ReadRegister(PCD_Register::RxModeReg) & 0x8F;

      // Set bit rate and enable CRC for T=CL
      txReg = (txReg & 0x8F) | ((receiveBitRate & 0x03) << 4) | 0x80;
      rxReg = (rxReg & 0x8F) | ((sendBitRate & 0x03) << 4) | 0x80;
      rxReg &= 0xF0; // Enforce although this should be set already

      // From ConfigIsoType
      // rxReg |= 0x06;

      _driver.PCD_WriteRegister(PCD_Register::TxModeReg, txReg);
      _driver.PCD_WriteRegister(PCD_Register::RxModeReg, rxReg);

      // At 212kBps
      switch (sendBitRate)
      {
      case BITRATE_212KBITS:
      {
        // _driver.PCD_WriteRegister(PCD_Register::ModWidthReg, 0x13);
        _driver.PCD_WriteRegister(PCD_Register::ModWidthReg, 0x15);
      }
      break;
      case BITRATE_424KBITS:
      {
        _driver.PCD_WriteRegister(PCD_Register::ModWidthReg, 0x0A);
      }
      break;
      case BITRATE_848KBITS:
      {
        _driver.PCD_WriteRegister(PCD_Register::ModWidthReg, 0x05);
      }
      break;
      default:
      {
        _driver.PCD_WriteRegister(PCD_Register::ModWidthReg, 0x26); // Default value
      }
      break;
      }

      // _driver.PCD_WriteRegister(RxThresholdReg, 0x84); // ISO-14443.4 Type A (default)
      // _driver.PCD_WriteRegister(ControlReg, 0x10);

      delayMicroseconds(10);
    }
    else
    {
      return StatusCode::STATUS_ERROR;
    }
  }

  return result;
} // End PICC_PPS()

/////////////////////////////////////////////////////////////////////////////////////
// Functions for communicating with ISO/IEC 14433-4 cards
/////////////////////////////////////////////////////////////////////////////////////

MFRC522::StatusCode MFRC522TCL::TCL_Transceive(PcbBlock *send, PcbBlock *back)
{
  MFRC522::StatusCode result;
  byte inBuffer[MFRC522::FIFO_SIZE];
  byte inBufferSize = sizeof(inBuffer);
  byte outBuffer[send->inf.size + 5]; // PCB + CID + NAD + INF + EPILOGUE (CRC)
  byte outBufferOffset = 1;
  byte inBufferOffset = 1;

  // Set the PCB byte
  outBuffer[0] = send->prologue.pcb;

  // Set the CID byte if available
  if (send->prologue.pcb & 0x08)
  {
    outBuffer[outBufferOffset] = send->prologue.cid;
    outBufferOffset++;
  }

  // Set the NAD byte if available
  if (send->prologue.pcb & 0x04)
  {
    outBuffer[outBufferOffset] = send->prologue.nad;
    outBufferOffset++;
  }

  // Copy the INF field if available
  if (send->inf.size > 0)
  {
    memcpy(&outBuffer[outBufferOffset], send->inf.data, send->inf.size);
    outBufferOffset += send->inf.size;
  }

  // Is the CRC enabled for transmission?
  byte txModeReg = _driver.PCD_ReadRegister(PCD_Register::TxModeReg);
  if ((txModeReg & 0x80) != 0x80)
  {
    // Calculate CRC_A
    result = _device.PCD_CalculateCRC(outBuffer, outBufferOffset, &outBuffer[outBufferOffset]);
    if (result != StatusCode::STATUS_OK)
    {
      return result;
    }

    outBufferOffset += 2;
  }

  // Transceive the block
  result = PCD_TransceiveDataEx(outBuffer, outBufferOffset, inBuffer, &inBufferSize);
  if (result != StatusCode::STATUS_OK)
  {
    return result;
  }

  // We want to turn the received array back to a PcbBlock
  back->prologue.pcb = inBuffer[0];

  // CID byte is present?
  if (send->prologue.pcb & 0x08)
  {
    back->prologue.cid = inBuffer[inBufferOffset];
    inBufferOffset++;
  }

  // NAD byte is present?
  if (send->prologue.pcb & 0x04)
  {
    back->prologue.nad = inBuffer[inBufferOffset];
    inBufferOffset++;
  }

  // Check if CRC is taken care of by MFRC522
  byte rxModeReg = _driver.PCD_ReadRegister(PCD_Register::RxModeReg);
  if ((rxModeReg & 0x80) != 0x80)
  {
    Serial.print("CRC is not taken care of by MFRC522: ");
    Serial.println(rxModeReg, HEX);

    // Check the CRC
    // We need at least the CRC_A value.
    if ((int)(inBufferSize - inBufferOffset) < 2)
    {
      return StatusCode::STATUS_CRC_WRONG;
    }

    // Verify CRC_A - do our own calculation and store the control in controlBuffer.
    byte controlBuffer[2];
    MFRC522::StatusCode status = _device.PCD_CalculateCRC(inBuffer, inBufferSize - 2, controlBuffer);
    if (status != StatusCode::STATUS_OK)
    {
      return status;
    }

    if ((inBuffer[inBufferSize - 2] != controlBuffer[0]) || (inBuffer[inBufferSize - 1] != controlBuffer[1]))
    {
      return StatusCode::STATUS_CRC_WRONG;
    }

    // Take away the CRC bytes
    inBufferSize -= 2;
  }

  // Got more data?
  if (inBufferSize > inBufferOffset)
  {
    if ((inBufferSize - inBufferOffset) > back->inf.size)
    {
      return StatusCode::STATUS_NO_ROOM;
    }

    memcpy(back->inf.data, &inBuffer[inBufferOffset], inBufferSize - inBufferOffset);
    back->inf.size = inBufferSize - inBufferOffset;
  }
  else
  {
    back->inf.size = 0;
  }

  // If the response is a R-Block check NACK
  if (((inBuffer[0] & 0xC0) == 0x80) && (inBuffer[0] & 0x20))
  {
    return StatusCode::STATUS_MIFARE_NACK;
  }

  return result;
}
/**
 * Send an I-Block (Application)
 */
MFRC522::StatusCode MFRC522TCL::TCL_Transceive(byte *sendData, byte sendLen, byte *backData, byte *backLen)
{
  MFRC522::StatusCode result;

  PcbBlock out;
  PcbBlock in;
  byte outBuffer[MFRC522::FIFO_SIZE];
  byte outBufferSize = sizeof(outBuffer);
  byte totalBackLen = *backLen;

  // This command sends an I-Block
  out.prologue.pcb = 0x02;

  if (ats.tc1.supportsCID)
  {
    out.prologue.pcb |= 0x08;
    out.prologue.cid = 0x00; // CID is curentlly hardcoded as 0x00
  }

  // This command doe not support NAD
  out.prologue.pcb &= 0xFB;
  out.prologue.nad = 0x00;

  // Set the block number
  if (blockToggle)
  {
    out.prologue.pcb |= 0x01;
  }

  // Do we have data to send?
  if (sendData && (sendLen > 0))
  {
    out.inf.size = sendLen;
    out.inf.data = sendData;
  }
  else
  {
    out.inf.size = 0;
    out.inf.data = NULL;
  }

  // Initialize the receiving data
  // TODO Warning: Value escapes the local scope
  in.inf.data = outBuffer;
  in.inf.size = outBufferSize;

  result = TCL_Transceive(&out, &in);
  if (result != StatusCode::STATUS_OK)
  {
    return result;
  }

  // Swap block number on success
  blockToggle = !blockToggle;

  if (backData && (*backLen > 0))
  {
    if (*backLen < in.inf.size)
      return StatusCode::STATUS_NO_ROOM;

    *backLen = in.inf.size;
    memcpy(backData, in.inf.data, in.inf.size);
  }

  // Check if the response is the final block
  bool finalBlock = (in.prologue.pcb & 0x10) == 0x00;

  // Send an ACK to receive more data if result is chained
  while (!finalBlock)
  {
    byte ackData[MFRC522::FIFO_SIZE];
    byte ackDataSize = sizeof(ackData);

    result = TCL_TransceiveRBlock(true, ackData, &ackDataSize, &finalBlock);
    if (result != StatusCode::STATUS_OK)
    {
      return result;
    }

    if (backData && (*backLen > 0))
    {
      if ((*backLen + ackDataSize) > totalBackLen)
        return StatusCode::STATUS_NO_ROOM;

      memcpy(&(backData[*backLen]), ackData, ackDataSize);
      *backLen += ackDataSize;
    }
  }

  return result;
} // End TCL_Transceive()

/**
 * Send R-Block to the PICC.
 */
MFRC522::StatusCode MFRC522TCL::TCL_TransceiveRBlock(bool ack, byte *backData, byte *backLen, bool *finalBlock)
{
  MFRC522::StatusCode result;

  PcbBlock out;
  PcbBlock in;
  byte outBuffer[MFRC522::FIFO_SIZE];
  byte outBufferSize = sizeof(outBuffer);

  // This command sends an R-Block
  if (ack)
    out.prologue.pcb = 0xA2; // ACK
  else
    out.prologue.pcb = 0xB2; // NAK

  if (ats.tc1.supportsCID)
  {
    out.prologue.pcb |= 0x08;
    out.prologue.cid = 0x00; // CID is curentlly hardcoded as 0x00
  }

  // This command doe not support NAD
  out.prologue.pcb &= 0xFB;
  out.prologue.nad = 0x00;

  // Set the block number
  if (blockToggle)
  {
    out.prologue.pcb |= 0x01;
  }

  // No INF data for R-Block
  out.inf.size = 0;
  out.inf.data = NULL;

  // Initialize the receiving data
  // TODO Warning: Value escapes the local scope
  in.inf.data = outBuffer;
  in.inf.size = outBufferSize;

  result = TCL_Transceive(&out, &in);
  if (result != StatusCode::STATUS_OK)
  {
    return result;
  }

  // Toggle block number bit on success
  blockToggle = !blockToggle;

  if (backData && backLen)
  {
    if (*backLen < in.inf.size)
      return StatusCode::STATUS_NO_ROOM;

    *backLen = in.inf.size;
    memcpy(backData, in.inf.data, in.inf.size);
  }

  // If chaining is not indicated, this is the final R-Block
  if (finalBlock)
    *finalBlock = (in.prologue.pcb & 0x10) == 0;

  return result;
} // End TCL_TransceiveRBlock()

/**
 * Send an S-Block to deselect the card.
 */
MFRC522::StatusCode MFRC522TCL::TCL_Deselect()
{
  MFRC522::StatusCode result;
  byte outBuffer[4];
  byte outBufferSize = 1;
  byte inBuffer[MFRC522::FIFO_SIZE];
  byte inBufferSize = sizeof(inBuffer);

  outBuffer[0] = 0xC2;
  if (ats.tc1.supportsCID)
  {
    outBuffer[0] |= 0x08;
    outBuffer[1] = 0x00; // CID is hardcoded
    outBufferSize = 2;
  }

  result = PCD_TransceiveDataEx(outBuffer, outBufferSize, inBuffer, &inBufferSize);
  if (result != StatusCode::STATUS_OK)
  {
    return result;
  }

  // TODO:Maybe do some checks? In my test it returns: CA 00 (Same data as I sent to my card)

  return result;
} // End TCL_Deselect()
