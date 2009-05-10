/*									tab:4
 *
 * "Copyright (c) 2000-2002 The Regents of the University  of California.  
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose, without fee, and without written agreement is
 * hereby granted, provided that the above copyright notice, the following
 * two paragraphs and the author appear in all copies of this software.
 * 
 * IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO ANY PARTY FOR
 * DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES ARISING OUT
 * OF THE USE OF THIS SOFTWARE AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF
 * CALIFORNIA HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS
 * ON AN "AS IS" BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
 * PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS."
 *
 * Authors: Naveen Sastry
 * Date:    10/20/02
 *
 * Basic header file descriptions for the crpto contexts. These are untyped
 * and meant to be opaque to all but the appropriate modules, which should
 * cast the structures to their appropriate internal types. 
 */

/*
 * Context for block cipher.
 */
typedef struct CipherContext {
  // rc5      needs 104 bytes
  // skipjack needs 32 * 4 = 128 bytes.
  uint8_t context[128];
} CipherContext;



/**
 * Context for the MAC
 */
typedef struct MACContext {
  CipherContext cc;
  uint8_t context[12];
} MACContext;

/**
 * Context for the block cipher modes
 */
typedef struct CipherModeContext {
  CipherContext cc;
  uint8_t context[24];
} CipherModeContext;
