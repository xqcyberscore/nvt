###############################################################################
# OpenVAS Include File
# $Id: smb_nt_legacy.inc 6410 2017-06-23 08:17:07Z cfischer $
#
# Methods for handling SMB (legacy/unused functions)
#
# Authors:
# Anonymous
#
# Copyright:
# Copyright (C) 2004 Anonymous
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
# $Revision: 6410 $
#
###############################################################################

# Those are functions moved from smb_nt.inc in here because they
# are currently unused. If you're planning to use any of these
# please take care of testing and updating those including
# updating the coding style and using local vars.

 #----------------------------------------------------------#
 # RegDelKey()						    #
 #----------------------------------------------------------#
 function registry_delete_key(soc, uid, tid, pipe, key, reply )
 {
 	local_var _na_start, i, error;

	key_len = strlen(key) + 1;
	key_len_hi = key_len / 256;
	key_len_lo = key_len % 256;

	tid_low = tid % 256;
	tid_high = tid / 256;
	uid_low = uid % 256;
	uid_high = uid / 256;
	pipe_low = pipe % 256;
	pipe_high = pipe / 256;
	uc = unicode3(data:key);

	len = 148 + strlen(uc);

	len_hi = len / 256;
	len_lo = len % 256;

 	z = 40 + strlen(uc);
	z_lo = z % 256;
	z_hi = z / 256;

	y = 81 + strlen(uc);
	y_lo = y % 256;
	y_hi = y / 256;

	x = 64 + strlen(uc);
	x_lo = x % 256;
	x_hi = x / 256;

	if(strlen(reply) < 18){
		return NULL;
	}
	magic1 = raw_string(ord(reply[16]), ord(reply[17]));

	req = raw_string(0x00, 0x00,
			 len_hi, len_lo, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
			 0x00, 0x00, 0x00, 0x18);
	if(ntlmssp_flag){
		g_mhi = multiplex_id / 256;
        	g_mlo = multiplex_id % 256;
		if(isSignActive)
			req += raw_string(0x07, 0x80);
		else
			req += raw_string(0x03, 0x80);
	}
	else{
		req += raw_string(0x03, 0x80);
	}
	req +=  magic1 +
	      	raw_string(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00,tid_low, tid_high);
	if(ntlmssp_flag)
		req += raw_string(0x33, 0x0c);
	else
		req += raw_string(0x00, 0x28);
	req += raw_string(uid_low, uid_high,
			 g_mlo, g_mhi, 0x10, 0x00, 0x00, x_lo, x_hi, 0x00,
			 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
			 0x00, x_lo, x_hi, 0x54, 0x00, 0x02, 0x00, 0x26,
			 0x00, pipe_low, pipe_high, y_lo, y_hi, 0x00, 0x5C, 0x00,
			 0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
			 0x5C, 0x00, 0x00, 0x00, 0x00, 0xb9, 0x05, 0x00,
			 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, x_lo, x_hi,
			 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, z_lo, z_hi,
			 0x00, 0x00, 0x00, 0x00, 0x07, 0x00);

    if(strlen(reply) < 85){
      return FALSE ;
    }	  
	magic = raw_string(ord(reply[84]));
	for(i=1; i<20; i=i+1){
      if(strlen(reply) > (84+i)){        
  	    magic = magic + raw_string(ord(reply[84+i]));
 	  }
    }
    
	x = strlen(key) + strlen(key) + 2;
	x_lo = x % 256;
	x_hi = x / 256;

	req = req + magic +
	      raw_string(x_lo, x_hi, x_lo, x_hi, 0x01, 0x00,
 			 0x00, 0x00, key_len_lo, key_len_hi, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, key_len_lo, key_len_hi, 0x00) + uc +
	      raw_string(0);

        # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
	if( ntlmssp_flag && isSignActive ) {
          len = strlen( req );
          seq_number += 1;
          packet = req;
          req = get_signature( key:s_sign_key, buf:packet, buflen:len, seq_number:seq_number );
          if( isnull( req ) ) return FALSE;
        }

 	send(socket:soc, data:req);
	r = smb_recv(socket:soc);
	if( strlen( r ) < 10 ) {
          return(1);
	}

	if( ntlmssp_flag ) {
          multiplex_id += 1;
          if( r && isSignActive ) {
            # verify signature
            seq_number += 1;
            len = strlen( r );
            server_resp = get_signature( key:s_sign_key, buf:r, buflen:len, seq_number:seq_number );
            if( isnull( server_resp ) ) return FALSE;

            #TODO: Also check the response length here before accessing possible non-existing data
            if((strlen(server_resp) < 24) || (len < 24)) {
              return(FALSE);
            }

            orig_sign = substr( r, 18, 23 );
            serv_sign = substr( server_resp, 18, 23 );
            if( orig_sign != serv_sign ) {
              return FALSE;
            }
          }
	}
        # -> END TODO
   	error = substr(r, strlen(r) - 4, strlen(r) - 1);
    if(strlen(error) < 4) {
      return NULL ;
    }
 	return ((int(ord(error[3])) * 256 + int(ord(error[2]))) * 256 +
    int(ord(error[1])) * 256) + int(ord(error[0]));
 }

 #----------------------------------------------------------#
 # RegDelValue()					    #
 #----------------------------------------------------------#
 function registry_delete_value(soc, uid, tid, pipe, value, reply )
 {
 	local_var _na_start, i, error;

	key_len = strlen(value) + 1;
	key_len_hi = key_len / 256;
	key_len_lo = key_len % 256;

 	tid_low = tid % 256;
	tid_high = tid / 256;
	uid_low = uid % 256;
	uid_high = uid / 256;
	pipe_low = pipe % 256;
	pipe_high = pipe / 256;
	uc = unicode3(data:value);

	len = 148 + strlen(uc);

	len_hi = len / 256;
	len_lo = len % 256;

 	z = 40 + strlen(uc);
	z_lo = z % 256;
	z_hi = z / 256;

	y = 81 + strlen(uc);
	y_lo = y % 256;
	y_hi = y / 256;

	x = 64 + strlen(uc);
	x_lo = x % 256;
	x_hi = x / 256;

	if(strlen(reply) < 18){
		return NULL;
	}

 	magic1 = raw_string(ord(reply[16]), ord(reply[17]));

	req = raw_string(0x00, 0x00,
 			 len_hi, len_lo, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
			 0x00, 0x00, 0x00, 0x18);
	if(ntlmssp_flag){
                g_mhi = multiplex_id / 256;
                g_mlo = multiplex_id % 256;
                if(isSignActive)
                        req += raw_string(0x07, 0x80);
                else
                        req += raw_string(0x03, 0x80);
        }
        else{
                req += raw_string(0x03, 0x80);
        }

	req += magic1 +
	      	raw_string(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00,tid_low, tid_high);
	if(ntlmssp_flag)
                req += raw_string(0x33, 0x0c);
        else
                req += raw_string(0x00, 0x28);
	req += raw_string(uid_low, uid_high,
			 g_mlo, g_mhi, 0x10, 0x00, 0x00, x_lo, x_hi, 0x00,
			 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
			 0x00, x_lo, x_hi, 0x54, 0x00, 0x02, 0x00, 0x26,
			 0x00, pipe_low, pipe_high, y_lo, y_hi, 0x00, 0x5C, 0x00,
			 0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
			 0x5C, 0x00, 0x00, 0x00, 0x00, 0xb9, 0x05, 0x00,
			 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, x_lo, x_hi,
			 0x00, 0x00, 0x97, 0x00, 0x00, 0x00, z_lo, z_hi,
			 0x00, 0x00, 0x00, 0x00, 0x08, 0x00);

    if(strlen(reply) < 85){
      return FALSE ;
    }		  
	magic = raw_string(ord(reply[84]));
	for(i=1; i<20; i=i+1){
      if(strlen(reply) > (84+i)){
  		magic = magic + raw_string(ord(reply[84+i]));
 	  }
    }
	x = strlen(value) + strlen(value) + 2;
	x_lo = x % 256;
	x_hi = x / 256;

	req = req + magic +
	      raw_string(x_lo, x_hi, x_lo, x_hi, 0x01, 0x00,
 			 0x00, 0x00, key_len_lo, key_len_hi, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, key_len_lo, key_len_hi, 0x00) + uc +
	      raw_string(0);

        # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
	if( ntlmssp_flag && isSignActive ) {
          len = strlen(req);
          seq_number += 1;
          packet = req;
          req = get_signature( key:s_sign_key, buf:packet, buflen:len, seq_number:seq_number );
          if( isnull( req ) ) return FALSE;
        }

	send( socket:soc, data:req );
	r = smb_recv( socket:soc );
	if( strlen( r ) < 10 ) {
          return(1);
	}

	if( ntlmssp_flag ) {
          multiplex_id += 1;
          if( r && isSignActive ) {
            # verify signature
            seq_number += 1;
            len = strlen( r );
            server_resp = get_signature( key:s_sign_key, buf:r, buflen:len, seq_number:seq_number );
            if( isnull( server_resp ) ) return FALSE;

            #TODO: Also check the response length here before accessing possible non-existing data
            if((strlen(server_resp) < 24) || (len < 24)) {
              return(FALSE);
            }
            orig_sign = substr( r, 18, 23 );
            serv_sign = substr( server_resp, 18, 23 );
            if( orig_sign != serv_sign ) {
              return FALSE;
            }
          }
        }
        # -> END TODO

	error = substr(r, strlen(r) - 4, strlen(r) - 1);
    if(strlen(error) < 4) {
      return NULL ;
    }

	return ((int(ord(error[3])) * 256 + int(ord(error[2]))) * 256 +
		 int(ord(error[1])) * 256) + int(ord(error[0]));
 }

 #--------------------------------------------------------------#
 # RegShutdown()                                                #
 #--------------------------------------------------------------#
 function registry_shutdown(soc, uid, tid, pipe, message, timeout, reboot, closeapps)
 {
 	local_var _na_start, i, error, msg_len, msg_len_hi, msg_len_lo, tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high, uc;

	msg_len = strlen(message) + 1;
	msg_len_hi = msg_len / 256;
	msg_len_lo = msg_len % 256;

 	tid_low = tid % 256;
	tid_high = tid / 256;
	uid_low = uid % 256;
	uid_high = uid / 256;
	pipe_low = pipe % 256;
	pipe_high = pipe / 256;
	uc = unicode4(data:message);

	len = 146 + strlen(uc);

	len_hi = len / 256;
	len_lo = len % 256;

 	z = 38 + strlen(uc);
	z_lo = z % 256;
	z_hi = z / 256;

	y = 79 + strlen(uc);
	y_lo = y % 256;
	y_hi = y / 256;

	x = 62 + strlen(uc);
	x_lo = x % 256;
	x_hi = x / 256;

 	req = raw_string(0x00, 0x00,
 		         len_hi, len_lo, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
			 0x00, 0x00, 0x00, 0x18);
	if(ntlmssp_flag){
                g_mhi = multiplex_id / 256;
                g_mlo = multiplex_id % 256;
                if(isSignActive)
                        req += raw_string(0x07, 0x80);
                else
                        req += raw_string(0x03, 0x80);
        }
        else{
                req += raw_string(0x03, 0x80);
        }

	req += raw_string(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00,tid_low, tid_high);
	if(ntlmssp_flag)
                req += raw_string(0x33, 0x0c);
        else
                req += raw_string(0x00, 0x28);
	req += raw_string(uid_low, uid_high,
			 g_mlo, g_mhi, 0x10, 0x00, 0x00, x_lo, x_hi, 0x00,
			 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
			 0x00, x_lo, x_hi, 0x54, 0x00, 0x02, 0x00, 0x26,
			 0x00, pipe_low, pipe_high, y_lo, y_hi, 0x00, 0x5C, 0x00,
			 0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
			 0x5C, 0x00, 0x00, 0x00, 0x00, 0xb9, 0x05, 0x00,
			 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, x_lo, x_hi,
			 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, z_lo, z_hi,
			 0x00, 0x00, 0x00, 0x00, 0x18, 0x00);

	x = strlen(message) + strlen(message);
	x_lo = x % 256;
	x_hi = x / 256;
	y = x + 2;
	y_lo = y % 256;
	y_hi = y / 256;

	msg_len2 = msg_len - 1;
	msg_len2_lo = msg_len2 % 256;
	msg_len2_hi = msg_len2 / 256;

	req += raw_string(0x01, 0x00, 0x00, 0x00,  # ptr_1
			  0x01, 0x00, 0x00, 0x00,  # ptr_2
			  0x01, 0x00, 0x00, 0x00,  # ptr_3
			  x_lo, x_hi,		     # uni_str_len
			  y_lo, y_hi,		     # max_str_len
			  0x01, 0x00, 0x00, 0x00,  # buffer
			  msg_len_lo, msg_len_hi, 0x00, 0x00,  # uni_max_len
			  0x00, 0x00, 0x00, 0x00 , # undoc
			  msg_len2_lo, msg_len2_hi, 0x00, 0x00);  # str_max_len
 	req += uc;
	req += raw_string(timeout % 256, (timeout/256) % 256, (timeout/(256*256)) % 256,
			  timeout / (256*256*256));
 	if( closeapps ) {
          req += raw_string(0x01);
        } else {
          req += raw_string(0x00);
        }

        if( reboot ) {
          req += raw_string(0x01);
	} else {
          req += raw_string(0x00);
	}

        # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
	if( ntlmssp_flag && isSignActive ) {
          len = strlen( req );
          seq_number += 1;
          packet = req;
          req = get_signature( key:s_sign_key, buf:req, buflen:len, seq_number:seq_number );
          if( isnull( req ) ) return FALSE;
        }

 	send( socket:soc, data:req );
	r = smb_recv( socket:soc );
	if( strlen( r ) < 10 ) {
          return( 1 );
	}

        if( ntlmssp_flag ) {
          multiplex_id += 1;
          if( r && isSignActive ) {
            # verify signature
            seq_number += 1;
            len = strlen( r );
            server_resp = get_signature( key:s_sign_key, buf:r, buflen:len, seq_number:seq_number );
            if( isnull( server_resp ) ) return FALSE;

            #TODO: Also check the response length here before accessing possible non-existing data
            if((strlen(server_resp) < 24) || (len < 24)) {
              return(FALSE);
            }

            orig_sign = substr( r, 18, 23 );
            serv_sign = substr( server_resp, 18, 23 );
            if( orig_sign != serv_sign ) {
              return FALSE;
            }
          }
        }
        # -> END TODO

	error = substr(r, strlen(r) - 4, strlen(r) - 1);
    if(strlen(error) < 4) {
      return NULL ;
    }
 	return ((int(ord(error[3])) * 256 + int(ord(error[2]))) * 256 +
		 int(ord(error[1])) * 256 ) + int(ord(error[0]));
 }


 #------------------------------------------------------------------#
 # Return TRUE if someone else than the admin group, the owner      #
 # and the local system can modify the key                          #
 #------------------------------------------------------------------#
 function registry_key_writeable_by_non_admin(security_descriptor)
 {
 	local_var r, num_aces, size, start, s, i, mask, z, id_auth, num_auth, sub_auth, k, n, sid;
	local_var WRITE, ADMIN_SID, LOCAL_SYSTEM_SID, CREATOR_OWNER_SID;

	if(isnull(security_descriptor)){
		return(NULL);
	}

	# write mask
	WRITE = 0x00010000 | 0x00040000 | 0x00080000 | 0x00000002 | 0x000004;

	# sids

	ADMIN_SID = "1-000005-32-544";
	LOCAL_SYSTEM_SID = "1-000005-18";
	CREATOR_OWNER_SID = "1-000003-0";

 	r = security_descriptor;
    if(strlen(r) < 156){
      return(NULL);
	}
	num_aces = 0;
	num_aces = ord(r[135]);
	num_aces = ord(r[134])+ num_aces*256;
	num_aces = ord(r[133])+ num_aces*256;
	num_aces = ord(r[132])+ num_aces*256;
	start = 137;
 	size = 0;
	s = start;

	for(i=0;i<num_aces;i=i+1)
 	{
		z = ord(r[s+2]);
		z = ord(r[s+1])+z*256;
		mask = ord(r[s+6]);
		mask = ord(r[s+5])+mask*256;
		mask = ord(r[s+4])+mask*256;
		mask = ord(r[s+3])+mask*256;

		id_auth = ord(r[s+14]);
		id_auth = string(ord(r[s+13]), id_auth);
		id_auth = string(ord(r[s+12]), id_auth);
		id_auth = string(ord(r[s+11]), id_auth);
		id_auth = string(ord(r[s+10]), id_auth);
		id_auth = string(ord(r[s+9]), id_auth);

		num_auths = ord(r[s+8]);
		sub_auths = "";
		k = 15;
		for(c = 0;c < num_auths; c = c+1)
		{
          if(strlen(r) > (s+k+3)){
			n = ord(r[s+k+3]);
			n = ord(r[s+k+2])+n*256;
			n = ord(r[s+k+1])+n*256;
			n = ord(r[s+k])+n*256;
			k = k + 4;
			sub_auths = string(sub_auths,"-",n);
          }
		}

		sid = string(ord(r[s+7]), "-", id_auth, sub_auths);
		# display("sid = ", sid, "\n");
		if(mask & WRITE)
		{
			#     display("writeable by ", sid, "\n");
			#	  display(mask & WRITE, "\n");

			if((sid != ADMIN_SID) && (sid != LOCAL_SYSTEM_SID) &&
	    		   (sid != CREATOR_OWNER_SID))
			{
				#display("sid != ", CREATOR_OWNER_SID, "\n");
				#display(mask, "\n");
				return(TRUE);
			}
      		}
		s = s + z;
 	}
	return(FALSE);
 }

 #---------------------------------------------------------------------#
 # returns 'TRUE' if <key> is writeable				       #
 #---------------------------------------------------------------------#
 function registry_get_acl(key)
 {
   local_var name, domain, _smb_port, login, pass, soc, r, uid, tid, pipe, ret, prot;

   name =  kb_smb_name();
   if(!name){
     return NULL;
   }

   domain = kb_smb_domain();
   _smb_port = kb_smb_transport();
   if(!_smb_port){
     return NULL;
   }

   if(!get_port_state(_smb_port)){
     return(FALSE);
   }

   login = kb_smb_login();
   pass  = kb_smb_password();

   if(!login){
     login = "";
   }
   if(!pass){
     pass = "";
   }

   soc = open_sock_tcp(_smb_port);
   if(!soc){
     return NULL;
   }

   # Request the session
   r = smb_session_request(soc:soc,  remote:name);
   if(!r){
     return(FALSE);
   }

   # Negotiate the protocol
   prot = smb_neg_prot(soc:soc);
   if(!prot){
     return(FALSE);
   }

   # Set up our session
   r = smb_session_setup(soc:soc, login:login, password:pass, domain:domain, prot:prot);
   if(!r){
      return(FALSE);
   }

     # and extract our uid
     uid = session_extract_uid(reply:r);
     if(!uid){
       return(NULL);
     }

     # Connect to the remote IPC and extract the TID
     # we are attributed
     r = smb_tconx(soc:soc, name:name, uid:uid, share:"IPC$");
     if(!r){
       return(NULL);
     }
     # and extract our tree id
     tid = tconx_extract_tid(reply:r);
     if(!tid){
       return(NULL);
     }

     # Create a pipe to \winreg
     r = smbntcreatex(soc:soc, uid:uid, tid:tid, name:"\winreg");
     if(!r){
       return(NULL);
     }
     # and extract its ID
     pipe = smbntcreatex_extract_pipe(reply:r);
     if(!pipe){
       return(FALSE);
     }

     # Setup things
     r = pipe_accessible_registry(soc:soc, uid:uid, tid:tid, pipe:pipe);
     if(!r){
       return(FALSE);
     }
     r = registry_open_hklm(soc:soc, uid:uid, tid:tid, pipe:pipe);
     if(!r){
       return(FALSE);
     }

     if(key){
       r2 = registry_get_key(soc:soc, uid:uid, tid:tid, pipe:pipe, key:key, reply:r);
     }
     else {
      r2 = r;
     }

     if(r2)
     {
       r3 = registry_get_key_security(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r2);
       if(!r3){
        return(FALSE);
       }
       registry_close(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r2);
       registry_close(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:r);
       close(soc);

       if(strlen(r3) < 100){
         return(NULL);
       }
       return(r3);
     }
     return(NULL);
   }

#---------------------------------------------------------------------#
# Get the security descriptor for a key                               #
#---------------------------------------------------------------------#
function registry_get_key_security( soc, uid, tid, pipe, reply ) {

  local_var ret;

  if( ord( reply[4]) == 254 ) {
    ret = registry2_get_key_security(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:reply);
    return(ret);
  } else {
    ret = registry1_get_key_security(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:reply);
    return(ret);
  }
}

 function registry1_get_key_security(soc, uid, tid, pipe, reply)
{
 	local_var magic, req, r, tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high;

	tid_low = tid % 256;
	tid_high = tid / 256;

	uid_low = uid % 256;
	uid_high = uid / 256;

	pipe_low = pipe % 256;
	pipe_high = pipe / 256;

	req = raw_string(0x00, 0x00,
 			 0x00, 0x90, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
			 0x00, 0x00, 0x00, 0x18);
	if(ntlmssp_flag){
                g_mhi = multiplex_id / 256;
                g_mlo = multiplex_id % 256;
                if(isSignActive)
                        req += raw_string(0x07, 0x80);
                else
                        req += raw_string(0x03, 0x80);
        }
        else{
                req += raw_string(0x03, 0x80);
        }
	req += raw_string(0x00, 0x83,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, tid_low, tid_high);
	if(ntlmssp_flag)
        	req += raw_string(0x33, 0x0c);
        else
                req += raw_string(0x00, 0x28);
	req += raw_string(uid_low, uid_high,
			 g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x3C, 0x00, 0x00,
			 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
			 0x00, 0x3C, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26,
			 0x00, pipe_low, pipe_high, 0x4D, 0x00, 0x00, 0x5C, 0x00,
			 0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
			 0x5C, 0x00, 0x00, 0x00, 0xEE, 0xD5, 0x05, 0x00,
			 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x3C, 0x00,
			 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x24, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00);

	if(strlen(reply) < 104){
		return(FALSE);
	}

	magic = raw_string(ord(reply[84]));
	for(i=1;i<20;i=i+1){
		magic = magic + raw_string(ord(reply[84+i]));
	}

	req = req + magic + raw_string(0x04) + crap(data:raw_string(0), length:15);

	send(socket:soc, data:req);
	r = smb_recv(socket:soc);
    if(strlen(r) < 16){
      return(FALSE);
	}

	len1 =  ord(r[strlen(r) - 16]);
	len2 = ord(r[strlen(r) - 15]);
	len3 = ord(r[strlen(r) - 14]);
	len4 = ord(r[strlen(r) - 13]);
	req = raw_string(0x00, 0x00,
 			 0x00, 0x9C, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
			 0x00, 0x00, 0x00, 0x18, 0x03, 0x80, 0x00, 0x83,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, tid_low, tid_high, 0x00, 0x28, uid_low, uid_high,
			 g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x48, 0x00, 0x00,
			 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
			 0x00, 0x48, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26,
			 0x00, pipe_low, pipe_high, 0x59, 0x00, 0x00, 0x5C, 0x00,
			 0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
			 0x5C, 0x00, 0x00, 0x00, 0xEE, 0xD5, 0x05, 0x00,
			 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00,
			 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x30, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00);

 	req = req + magic +
	      raw_string(0x04, 0x00, 0x00, 0x00, 0x38, 0x8d,
			 0x07, 0x00, len1, len2, len3, len4, 0x00, 0x00,
			 0x00, 0x00, len1, len2, len3, len4, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

        # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
        if( ntlmssp_flag && isSignActive ) {
          len = strlen( req );
          seq_number += 1;
          packet = req;
          req = get_signature( key:s_sign_key, buf:req, buflen:len, seq_number:seq_number );
          if( isnull( req ) ) return FALSE;
        }

        send( socket:soc, data:req );
        r = smb_recv(socket:soc);
        if( strlen( r ) < 150 ) {
          return NULL;
        }

        if( ntlmssp_flag ) {
          multiplex_id += 1;
          if( r && isSignActive ) {
            # verify signature
            seq_number += 1;
            len = strlen( r );
            server_resp = get_signature( key:s_sign_key, buf:r, buflen:len, seq_number:seq_number );
            if( isnull( server_resp ) ) return FALSE;

            #TODO: Also check the response length here before accessing possible non-existing data
            if((strlen(server_resp) < 24) || (len < 24)) {
              return(FALSE);
            }
            orig_sign = substr( r, 18, 23 );
            serv_sign = substr( server_resp, 18, 23 );
            if( orig_sign != serv_sign ) {
              return FALSE;
            }
          }
        }
        # -> END TODO

  return r;
}

 function registry2_get_key_security(soc, uid, tid, pipe, reply)
 {
   local_var magic, req, r, tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high;

   g_mhi = multiplex_id / 256;
   g_mlo = multiplex_id % 256;

  req = raw_string(0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x01, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x6f, 0x00);

   if(isSignActive){
                 req += raw_string(0x08, 0x00, 0x00, 0x00);
   }
   else {
                 req += raw_string(0x00, 0x00, 0x00, 0x00);
   }
  req += raw_string(0x00, 0x00, 0x00, 0x00,
                   g_mlo, g_mhi, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, tid, uid, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

# Ioctl Req
  ioctl_req = raw_string(0x39, 0x00, 0x00, 0x00, 0x17, 0xc0, 0x11, 0x00,
                         pipe, 0x78, 0x00, 0x00, 0x00);

# Distributed Computing Environment / Remote Procedure Calls
 dcerpc_req1 = raw_string(0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00);
 dcerpc_req2 = raw_string(0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x34, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00);

  if(strlen(reply) < 141){
    return FALSE;
  }

  magic = raw_string(ord(reply[140]));
  for(i=1; i<20; i=i+1){
      if(strlen(reply) > (140+i)){
        magic = magic + raw_string(ord(reply[140+i]));
      }
  }

  x = strlen(key) + strlen(key) + 2;
  x_lo = x % 256;
  x_hi = x / 256;

# Remote Registry Service Req
  rrs_req = magic + raw_string(0x04) + crap(data:raw_string(0), length:15);

  len_rrs = strlen(rrs_req) + strlen(dcerpc_req1) + strlen(dcerpc_req2) + 2;
  len_rrs_lo = len_rrs % 256;
  len_rrs_hi = len_rrs / 256;

  dcerpc_req = dcerpc_req1 + raw_string(len_rrs_lo, len_rrs_hi) + dcerpc_req2;

  ioctl_req += raw_string(len_rrs_lo, len_rrs_hi, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00);

  req = req + ioctl_req + dcerpc_req + rrs_req;
  req_l = strlen(req);
  len_lo =  req_l % 256;
  len_hi = req_l / 256;

   if(isSignActive)
    {
         sig = get_smb2_signature(buf:req, key:sign_key);
         if( isnull( sig ) ) {
           set_kb_item( name:"nvt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#registry2_get_key_security: buf or key passed to get_smb2_signature empty / too short" );
           return FALSE;
         }
         req = raw_string(0x00, 0x00, len_hi, len_lo) + sig;
    }
    else{
         req = raw_string(0x00, 0x00, len_hi, len_lo) + req ;
    }

        send(socket:soc, data:req);
        r = smb_recv(socket:soc);
  if(strlen(r) < 14){
     return(FALSE);
  }

        ##If status is pending, wait for response
        status = ord(r[12]);
        status2 = ord(r[13]);
        while(status == 3 && status2 == 1)
        {
           ##PDU will arrive late
           r = smb_recv(socket:soc);
           if(strlen(r) < 14){
             return(FALSE);
           }
           status = ord(r[12]);
           status2 = ord(r[13]);
        }


  multiplex_id = multiplex_id + 1;
  g_mhi = multiplex_id / 256;
  g_mlo = multiplex_id % 256;

  if(strlen(r) < 16){
      return(FALSE);
  }

 len1 =  ord(r[strlen(r) - 16]);
 len2 = ord(r[strlen(r) - 15]);
 len3 = ord(r[strlen(r) - 14]);
 len4 = ord(r[strlen(r) - 13]);

  req = raw_string(0xfe, 0x53, 0x4d, 0x42, 0x40, 0x00, 0x01, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x6f, 0x00);

   if(isSignActive){
                 req += raw_string(0x08, 0x00, 0x00, 0x00);
   }
   else {
                 req += raw_string(0x00, 0x00, 0x00, 0x00);
   }


   req += raw_string(0x00, 0x00, 0x00, 0x00,
                   g_mlo, g_mhi, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, tid, uid, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

# Ioctl Req
  ioctl_req = raw_string(0x39, 0x00, 0x00, 0x00, 0x17, 0xc0, 0x11, 0x00,
                         pipe, 0x78, 0x00, 0x00, 0x00);

# Distributed Computing Environment / Remote Procedure Calls
 dcerpc_req1 = raw_string(0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00);
 dcerpc_req2 = raw_string(0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x34, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00);

  if(strlen(reply) < 141){
    return FALSE;
  }

  magic = raw_string(ord(reply[140]));
  for(i=1; i<20; i=i+1){
      if(strlen(reply) > (140+i)){
        magic = magic + raw_string(ord(reply[140+i]));
      }
  }

  x = strlen(key) + strlen(key) + 2;
  x_lo = x % 256;
  x_hi = x / 256;

# Remote Registry Service Req
  rrs_req = magic + raw_string(0x04, 0x00, 0x00, 0x00, 0x38, 0x8d, 0x07, 0x00,
            len1, len2, len3, len4, 0x00, 0x00, 0x00, 0x00, len1, len2, len3,
            len4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

  len_rrs = strlen(rrs_req) + strlen(dcerpc_req1) + strlen(dcerpc_req2) + 2;
  len_rrs_lo = len_rrs % 256;
  len_rrs_hi = len_rrs / 256;

  dcerpc_req = dcerpc_req1 + raw_string(len_rrs_lo, len_rrs_hi) + dcerpc_req2;

  ioctl_req += raw_string(len_rrs_lo, len_rrs_hi, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00);

  req = req + ioctl_req + dcerpc_req + rrs_req;
  req_l = strlen(req);
  len_lo =  req_l % 256;
  len_hi = req_l / 256;

   if(isSignActive)
    {
         sig = get_smb2_signature(buf:req, key:sign_key);
         if( isnull( sig ) ) {
           set_kb_item( name:"nvt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#registry2_get_key_security: buf or key passed to get_smb2_signature empty / too short" );
           return FALSE;
         }
         req = raw_string(0x00, 0x00, len_hi, len_lo) + sig;
    }
    else{
         req = raw_string(0x00, 0x00, len_hi, len_lo) + req ;
    }

          # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
        send(socket:soc, data:req);
        r = smb_recv(socket:soc);

        if(strlen(r) < 14){
          return(NULL);
        }

        ##If status is pending, wait for response
        status = ord(r[12]);
        status2 = ord(r[13]);
        while(status == 3 && status2 == 1)
        {
           ##PDU will arrive late
           r = smb_recv(socket:soc);
           if(strlen(r) < 14){
             return(NULL);
           }

           status = ord(r[12]);
           status2 = ord(r[13]);
        }


 if(strlen(r) < 150){
  return(NULL);
 }
 if(ntlmssp_flag){
          multiplex_id += 1;
          if(r && isSignActive){
               # verify signature
               seq_number += 1;
             r_head = substr(r, 0, 3);
             r = substr(r, 4, strlen(r)-1);
             if( strlen( r ) < 64 ) {
               return(FALSE);
             }

             orig_sign = substr(r, 48, 63);

             server_resp = get_smb2_signature(buf:r, key:sign_key);
             if( isnull( server_resp ) ) return FALSE;
             if( strlen(server_resp) < 64 ) {
               return(FALSE);
             }

             serv_sign = substr(server_resp, 48, 63);
             if(orig_sign != serv_sign){
              return(FALSE);
             }
             else {
               r = r_head + r ;
             }
        }
    }
        # END TODO ->

 return(r);
 }

 #----------------------------------------------------------#
 # RegFlush()						    #
 #----------------------------------------------------------#
 function registry_flush_NTLMSSP(soc, uid, tid, pipe, reply)
 {
        local_var magic, req, r, tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high, name, data, i, len;

        tid_low = tid % 256;
        tid_high = tid / 256;

        uid_low = uid % 256;
        uid_high = uid / 256;

        pipe_low = pipe % 256;
        pipe_high = pipe / 256;

	g_mhi = multiplex_id / 256;
        g_mlo = multiplex_id % 256;

        if(strlen(reply) < 85) {
          return FALSE ;
        }
        magic = raw_string(ord(reply[84]));
        for(i=1; i<20; i=i+1){
          if(strlen(reply) > (84+i)) {
            magic = magic + raw_string(ord(reply[84+i]));
          }
        }

        req = raw_string(0x00, 0x00, 0x00, 0x78, 0xFF, 0x53,
                         0x4D, 0x42, 0x25, 0x00, 0x00, 0x00, 0x00, 0x08);
	if(isSignActive)
		req += raw_string(0x05, 0x40);
	else
                req += raw_string(0x01, 0x40);
	req += raw_string(0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, tid_low, tid_high,
                         0x33, 0x0c, uid_low, uid_high, g_mlo, g_mhi, 0x10, 0x00,
                         0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x4c, 0x00, 0x2c, 0x00, 0x4c,
                         0x00, 0x02, 0x00, 0x26, 0x00, pipe_low, pipe_high, 0x35,
                         0x00, 0x5c, 0x50, 0x49, 0x50, 0x45, 0x5c, 0x00,
                         0x00, 0x00, 0x05, 0x00, 0x00, 0x03, 0x10, 0x00,
                         0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0xcf, 0x01,
                         0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x0b, 0x00) + magic;

        # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
	if( isSignActive ) {
          len = strlen( req );
          seq_number += 1;
          packet = req;
          req = get_signature( key:s_sign_key, buf:req, buflen:len, seq_number:seq_number );
          if( isnull( req ) ) return FALSE;
        }

        send( socket:soc, data:req );
        r = smb_recv( socket:soc );
	multiplex_id += 1;
        if( r && isSignActive ) {
          # verify signature
          seq_number += 1;
          len = strlen( r );
          server_resp = get_signature( key:s_sign_key, buf:r, buflen:len, seq_number:seq_number );
          if( isnull( server_resp ) ) return FALSE;

          #TODO: Also check the response length here before accessing possible non-existing data
          if((strlen(server_resp) < 24) || (len < 24)) {
            return(FALSE);
          }
          orig_sign = substr( r, 18, 23 );
          serv_sign = substr( server_resp, 18, 23 );
          if( orig_sign != serv_sign ) {
            return FALSE;
          }
        }
        # -> END TODO

        if( r ) {
          return substr(r, strlen(r) - 4, strlen(r) - 1);
        }
}

function registry_flush( soc, uid, tid, pipe, reply ) {

  local_var response;

  if( ntlmssp_flag ) {
    response = registry_flush_NTLMSSP(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:reply);
    return(response);
  } else {

 	local_var magic, req, r, tid_low, tid_high, uid_low, uid_high, pipe_low, pipe_high, name, data, i, len;

 	tid_low = tid % 256;
	tid_high = tid / 256;

	uid_low = uid % 256;
	uid_high = uid / 256;

	pipe_low = pipe % 256;
	pipe_high = pipe / 256;

    if(strlen(reply) < 85) {
      return FALSE ;
    } 
    magic = raw_string(ord(reply[84]));
	for(i=1; i<20; i=i+1){
      if(strlen(reply) > (84+i)){
        magic = magic + raw_string(ord(reply[84+i]));
 	  }
    }
    
 	req = raw_string(0x00, 0x00, 0x00, 0x78, 0xFF, 0x53,
			 0x4D, 0x42, 0x25, 0x00, 0x00, 0x00, 0x00, 0x08,
			 0x01, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, tid_low, tid_high,
			 0x00, 0x28, uid_low, uid_high, g_mlo, g_mhi, 0x10, 0x00,
			 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x4c, 0x00, 0x2c, 0x00, 0x4c,
			 0x00, 0x02, 0x00, 0x26, 0x00, pipe_low, pipe_high, 0x35,
			 0x00, 0x5c, 0x50, 0x49, 0x50, 0x45, 0x5c, 0x00,
			 0x00, 0x00, 0x05, 0x00, 0x00, 0x03, 0x10, 0x00,
			 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0xcf, 0x01,
			 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x0b, 0x00) + magic;

 	send(socket:soc, data:req);
	r = smb_recv(socket:soc);
    if(strlen(r) < 4){
      return(FALSE);
    }
 	if(r){
		return substr(r, strlen(r) - 4, strlen(r) - 1);
 	}
  }
}

#---------------------------------------------------------------------------#
# SAM related functions							    #
#---------------------------------------------------------------------------#



 #------------------------------------------------------#
 # Connects to the remote SAM                           #
 #------------------------------------------------------#
 function SamrConnect2(soc, tid, uid, pipe, name)
 {
	local_var i;
 	samr_smbwritex(soc:soc, tid:tid, uid:uid, pipe:pipe);
	samr_smbreadx(soc:soc, tid:tid, uid:uid, pipe:pipe);

	l = strlen(name);
	odd = l % 2;

	if(odd){
		p = 0;
	}
	else {
		p = 2;
	}

	tid_hi = tid / 256;
	tid_lo = tid % 256;
	uid_hi = uid / 256;
	uid_lo = uid % 256;

	pipe_hi = pipe / 256;
	pipe_lo = pipe % 256;

 	l = 3 + strlen(name);
	l_h = l / 256;
	l_l = l % 256;

	tot_len = 134 + strlen(name) + strlen(name) + p;
	tot_len_h = tot_len / 256;
	tot_len_l = tot_len % 256;

	bcc = 67 + strlen(name) + strlen(name) + p;
	bcc_lo = bcc % 256;
	bcc_hi = bcc / 256;

	total_data_count = 50 + strlen(name) + strlen(name) + p;
	total_data_count_lo = total_data_count % 256;
	total_data_count_hi = total_data_count / 256;

	req = raw_string(0x00, 0x00,
 			 tot_len_h, tot_len_l, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
			 0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
			 g_mlo, g_mhi, 0x10, 0x00, 0x00,total_data_count_lo, total_data_count_hi, 0x00,
			 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
			 0x00, total_data_count_lo, total_data_count_hi, 0x54, 0x00, 0x02, 0x00, 0x26,
			 0x00, pipe_lo, pipe_hi, bcc_lo, bcc_hi, 0x00, 0x5C, 0x00,
			 0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
			 0x5C, 0x00, 0x00, 0x00, 0xAF, 0x47, 0x05, 0x00,
			 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, total_data_count_lo, total_data_count_hi,
			 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x28, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x39, 0x00, 0x60, 0x60,
			 0x13, 0x00, l_l, l_h, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, l_l, l_h, 0x00, 0x00, 0x5C, 0x00,
			 0x5C) + samr_uc(name:name) + raw_string(0x00, 0x00, 0x00);

	if(p){
		req = req + raw_string(0xC9, 0x11); # 0x02, 0x00, 0x00, 0x00);
	}

	req = req +  raw_string(0x30, 0x00, 0x00, 0x00);
	#display(strlen(req), "\n");
	send(socket:soc, data:req);
	r = smb_recv(socket:soc);
	#display("--->", strlen(r), "\n");

 	# We return a handle to the remote SAM
	samrhdl = "";
	_len = strlen(r);
	if(_len < 24){
		return(FALSE);
	}

	_len = _len - 24;
	for(i=0; i<20; i=i+1)
	{
		samrhdl = samrhdl + raw_string(ord(r[i+_len]));
		#display(hex(ord(r[i+_len])), " ");
	}
	#display("\n");
	#display("samhdl : ", strlen(samrhdl), "\n");
	return (samrhdl);
 }

function samr_smbwritex( soc, tid, uid, pipe ) {

  local_var response;

  if( ntlmssp_flag ) {
    response = samr_smbwritex_NTLMSSP(soc:soc, tid:tid, uid:uid, pipe:pipe);
    return response;
  } else {
 	tid_hi = tid / 256;
	tid_lo = tid % 256;

	uid_hi = uid / 256;
	uid_lo = uid % 256;

	pipe_hi = pipe / 256;
	pipe_lo = pipe % 256;

	req = raw_string(0x00, 0x00,
 			 0x00, 0x88, 0xFF, 0x53, 0x4D, 0x42, 0x2F, 0x00,
			 0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
			 g_mlo, g_mhi, 0x0E, 0xFF, 0x00, 0xDE, 0xDE, pipe_lo,
			 pipe_hi, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
			 0xFF, 0x08, 0x00, 0x48, 0x00, 0x00, 0x00, 0x48,
			 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x49,
			 0x00, 0xEE, 0x05, 0x00, 0x0B, 0x03, 0x10, 0x00,
			 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00,
			 0x00, 0x00, 0xB8, 0x10, 0xB8, 0x10, 0x00, 0x00,
			 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x01, 0x00, 0x78, 0x57, 0x34, 0x12, 0x34, 0x12,
			 0xCD, 0xAB, 0xEF, 0x00, 0x01, 0x23, 0x45, 0x67,
			 0x89, 0xAC, 0x01, 0x00, 0x00, 0x00, 0x04, 0x5D,
			 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8,
			 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60, 0x02, 0x00,
			 0x00, 0x00);

	send(socket:soc, data:req);
	r = smb_recv(socket:soc);
  }
}

function samr_smbwritex_NTLMSSP(soc, tid, uid, pipe) {

        tid_hi = tid / 256;
        tid_lo = tid % 256;

        uid_hi = uid / 256;
        uid_lo = uid % 256;

        pipe_hi = pipe / 256;
        pipe_lo = pipe % 256;

	g_mhi = multiplex_id / 256;
        g_mlo = multiplex_id % 256;

        req = raw_string(0x00, 0x00,
                         0x00, 0x88, 0xFF, 0x53, 0x4D, 0x42, 0x2F, 0x00,
                         0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, tid_lo, tid_hi, 0x33, 0x0c, uid_lo, uid_hi,
                         g_mlo, g_mhi, 0x0E, 0xFF, 0x00, 0xDE, 0xDE, pipe_lo,
                         pipe_hi, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF,
                         0xFF, 0x08, 0x00, 0x48, 0x00, 0x00, 0x00, 0x48,
                         0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x49,
                         0x00, 0xEE, 0x05, 0x00, 0x0B, 0x03, 0x10, 0x00,
                         0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x01, 0x00,
                         0x00, 0x00, 0xB8, 0x10, 0xB8, 0x10, 0x00, 0x00,
                         0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x01, 0x00, 0x78, 0x57, 0x34, 0x12, 0x34, 0x12,
                         0xCD, 0xAB, 0xEF, 0x00, 0x01, 0x23, 0x45, 0x67,
                         0x89, 0xAC, 0x01, 0x00, 0x00, 0x00, 0x04, 0x5D,
                         0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8,
                         0x08, 0x00, 0x2B, 0x10, 0x48, 0x60, 0x02, 0x00,
                         0x00, 0x00);

        # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
        if( isSignActive ) {
          len = strlen( req );
          seq_number += 1;
          packet = req;
          req = get_signature( key:s_sign_key, buf:req, buflen:len, seq_number:seq_number );
          if( isnull( req ) ) return FALSE;
        }

        send( socket:soc, data:req );
        r = smb_recv( socket:soc );

	multiplex_id += 1;
        if( r && isSignActive ) {
          # verify signature
          seq_number += 1;
          len = strlen( r );
          server_resp = get_signature( key:s_sign_key, buf:r, buflen:len, seq_number:seq_number );
          if( isnull( server_resp ) ) return FALSE;

          #TODO: Also check the response length here before accessing possible non-existing data
          if((strlen(server_resp) < 24) || (len < 24)) {
            return(FALSE);
          }

          orig_sign = substr( r, 18, 23 );
          serv_sign = substr( server_resp, 18, 23 );
          if( orig_sign != serv_sign ) {
            return FALSE;
          }
        }
        # -> END TODO

  return r;
}

 function samr_smbreadx(soc, tid, uid, pipe)
 {
 	tid_hi = tid / 256;
	tid_lo = tid % 256;
	uid_hi = uid / 256;
	uid_lo = uid % 256;
	pipe_hi = pipe / 256;
	pipe_lo = pipe % 256;
	req = raw_string(0x00, 0x00,
 			 0x00, 0x3B, 0xFF, 0x53, 0x4D, 0x42, 0x2E, 0x00,
			 0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
			 g_mlo, g_mhi, 0x0C, 0xFF, 0x00, 0xDE, 0xDE, pipe_lo,
			 pipe_hi, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
			 0x04, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x04, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00);

	send(socket:soc, data:req);
	r = smb_recv(socket:soc);
 }

 #------------------------------------------------------#
 # Converts a username to its rid                       #
 #------------------------------------------------------#
 function SamrLookupNames(soc, uid, tid, pipe, name, domhdl)
 {
 	tid_hi = tid / 256;
	tid_lo = tid % 256;
	uid_hi = uid / 256;
	uid_lo = uid % 256;

	pipe_hi = pipe / 256;
	pipe_lo = pipe % 256;

	usr = samr_uc(name:name);
	len = 164 + strlen(usr);
	len_hi = len / 256;
	len_lo = len % 256;

	tdc = 80 + strlen(usr);
	tdc_l = tdc % 256;
	tdc_h = tdc / 256;

	bcc = tdc + 17;
	bcc_l = bcc % 256;
	bcc_h = bcc / 256;

	x = strlen(usr) / 2;
	x_h = x / 256;
	x_l = x % 256;

	y = x + 1;
	y_h = y / 256;
	y_l = y % 256;

	z = strlen(usr);
	z_l = z % 256;
	z_h = z / 256;

	t = z + 2;
	t_l = t % 256;
	t_h = t / 256;

	req = raw_string(0x00, 0x00,
 			 len_hi, len_lo, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
			 0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
			 g_mlo, g_mhi, 0x10, 0x00, 0x00, tdc_l, tdc_h, 0x00,
			 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
			 0x00, tdc_l, tdc_h, 0x54, 0x00, 0x02, 0x00, 0x26,
			 0x00, pipe_lo, pipe_hi, bcc_l, bcc_h, 0x00, 0x5C, 0x00,
			 0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
			 0x5C, 0x00, 0x00, 0x00, 0xAF, 0x47, 0x05, 0x00,
			 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, tdc_l, tdc_h,
			 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x44, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x11, 0x00) + domhdl +
	      raw_string(0x01, 0x00, 0x00, 0x00, 0xE8, 0x03,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
			 0x00, 0x00, z_l, z_h, t_l, t_h, 0xD8, 0x0E,
			 0x41, 0x00, y_l, y_h, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, x_l, x_h, 0x00) + usr +
              raw_string(0x00);

	send(socket:soc, data:req);
	r = smb_recv(socket:soc);

	if(strlen(r) < 100){
		return(FALSE);
	}

	_rid = "";
	#display("RID : ");
	_z = 0;
	for(i=0; i<4; i=i+1)
	{
		if(ord(r[96+i]) == 0){
			_z = _z + 1;
		}
		#display(hex(ord(r[96+i])), " ");
		_rid = _rid + raw_string(ord(r[96+i]));
	}
	#display("\n");
	if(_z == 4){
		return(NULL);
	}
	return(_rid);
 }

#------------------------------------------------------#
# Returns the unicode representation of <name>         #
#------------------------------------------------------#
function samr_uc( name ) {

  local_var i, ret;

  ret = "";

  for( i = 0; i < strlen( name ); i++ ) {
    ret += raw_string(0) + name[i];
  }
  return(ret);
}

 #--------------------------------------------------------------#
 # This function is probably SamrEnumerateDomainsInSamServer()  #
 # but I'm not sure of that, so I changed its name to           #
 # _SamrEnumDomains()                                           #
 #                                                              #
 # This function only returns the first domain it obtains       #
 #--------------------------------------------------------------#
 function _SamrEnumDomains(soc, uid, tid, pipe, samrhdl)
 {
	local_var i;
 	tid_hi = tid / 256;
	tid_lo = tid % 256;
	uid_hi = uid / 256;
	uid_lo = uid % 256;

	pipe_hi = pipe / 256;
	pipe_lo = pipe % 256;

	req = raw_string(0x00, 0x00,
 			 0x00, 0x88, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
			 0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
			 g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x34, 0x00, 0x00,
			 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
			 0x00, 0x34, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26,
			 0x00, pipe_lo, pipe_hi, 0x45, 0x00, 0x00, 0x5C, 0x00,
			 0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
			 0x5C, 0x00, 0x00, 0x00, 0xAF, 0x47, 0x05, 0x00,
			 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x34, 0x00,
			 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x1C, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x06, 0x00) + samrhdl +
	      raw_string(0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00);

	send(socket:soc, data:req);
	r = smb_recv(socket:soc);
	if(strlen(r) < 137){
		return(FALSE);
	}

	len_lo = ord(r[136]);
	len_hi = ord(r[137]);

	len = len_hi * 256;
	len = len + len_lo;
	dom = "";
	len = len*2;
	maxlen = strlen(r);
	if(maxlen < len)return(FALSE);
	for(i=0; i<len; i=i+2)
	{
  		if(maxlen < 139+i){
			return(FALSE);
		}
		dom = dom + raw_string(ord(r[139+i]), ord(r[140+i]));
 	}
	#display(dom, "\n");
	return(dom);
 }

 #------------------------------------------------------#
 # Open a pipe to \samr                                 #
 #------------------------------------------------------#
 function OpenPipeToSamr(soc, uid, tid)
 {
	tid_hi = tid / 256;
	tid_lo = tid % 256;

	uid_hi = uid / 256;
	uid_lo = uid % 256;

 	req = raw_string(0x00, 0x00,
 			 0x00, 0x60, 0xFF, 0x53, 0x4D, 0x42, 0xA2, 0x00,
			 0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, tid_lo, tid_hi);
	if(ntlmssp_flag){
		 g_mhi = multiplex_id / 256;
        	 g_mlo = multiplex_id % 256;
                req += raw_string(0x33, 0x0c);
	}
        else
                req += raw_string(0x00, 0x28);

	req += raw_string(uid_lo, uid_hi,
			 g_mlo, g_mhi, 0x18, 0xFF, 0x00, 0xDE, 0xDE, 0x00,
			 0x0A, 0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x9F, 0x01, 0x02, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00,
			 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x02, 0x00,
			 0x00, 0x00, 0x03, 0x0D, 0x00, 0x00, 0x5C, 0x00,
			 0x73, 0x00, 0x61, 0x00, 0x6D, 0x00, 0x72, 0x00,
			 0x00, 0x00);

        # <- START TODO: Deduplicate this code, this is duplicated many times in this include...
        if( ntlmssp_flag && isSignActive ) {
          len = strlen( req );
          seq_number += 1;
          packet = req;
          req = get_signature( key:s_sign_key, buf:req, buflen:len, seq_number:seq_number );
          if( isnull( req ) ) return FALSE;
        }

        send( socket:soc, data:req );
        r = smb_recv( socket:soc );

        if( ntlmssp_flag ) {
          multiplex_id += 1;
          if( r && isSignActive ) {
            # verify signature
            seq_number += 1;
            len = strlen( r );
            server_resp = get_signature( key:s_sign_key, buf:r, buflen:len, seq_number:seq_number );
            if( isnull( server_resp ) ) return FALSE;

            #TODO: Also check the response length here before accessing possible non-existing data
            if((strlen(server_resp) < 24) || (len < 24)) {
              return(FALSE);
            }

            orig_sign = substr( r, 18, 23 );
            serv_sign = substr( server_resp, 18, 23 );
            if( orig_sign != serv_sign ) {
              return FALSE;
            }
          }
        }
        # -> END TODO

        if( strlen( r ) < 44 ) {
          return( FALSE );
	} else {
          low = ord(r[42]);
          hi  = ord(r[43]);
          ret = hi * 256;
          ret = ret + low;
          return(ret);
        }
}

 #------------------------------------------------------#
 # Returns the sid from the domain <dom>                #
 #------------------------------------------------------#
 function SamrDom2Sid(soc, tid, uid, pipe, samrhdl, dom)
 {
 	tid_hi = tid / 256;
	tid_lo = tid % 256;
	uid_hi = uid / 256;
	uid_lo = uid % 256;

	pipe_hi = pipe / 256;
	pipe_lo = pipe % 256;

	#display(strlen(dom), "<-dom\n");
	tot_len = 148 + strlen(dom);
	tot_len_hi = tot_len / 256;
	tot_len_lo = tot_len % 256;

	bcc = 81 + strlen(dom);
	bcc_lo = bcc % 256;
	bcc_hi = bcc / 256;

	tot_dat_count = 64 + strlen(dom);
	tot_dat_count_lo = tot_dat_count % 256;
	tot_dat_count_hi = tot_dat_count / 256;

	dom_len = strlen(dom);
	dom_len = dom_len / 2;
	dom_len_lo = dom_len % 256;
	dom_len_hi = dom_len / 256;

	dom_t_len =  dom_len + 1;
	dom_t_len_lo = dom_t_len % 256;
	dom_t_len_hi = dom_t_len / 256;

	dom_m_len = dom_len * 2;
	dom_m_len_lo = dom_m_len % 256;
	dom_m_len_hi = dom_m_len / 256;

	dom_mm_len = dom_m_len + 2;
	dom_mm_len_lo = dom_mm_len % 256;
	dom_mm_len_hi = dom_mm_len / 256;

 	req = raw_string(0x00, 0x00,
 			 tot_len_hi, tot_len_lo, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
			 0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
			 g_mlo, g_mhi, 0x10, 0x00, 0x00, tot_dat_count_lo, tot_dat_count_hi, 0x00,
			 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
			 0x00, tot_dat_count_lo, tot_dat_count_hi, 0x54, 0x00, 0x02, 0x00, 0x26,
			 0x00, pipe_lo, pipe_hi, bcc_lo, bcc_hi, 0x00, 0x5C, 0x00,
			 0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
			 0x5C, 0x00, 0x00, 0x00, 0xAF, 0x47, 0x05, 0x00,
			 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, tot_dat_count_lo, tot_dat_count_hi,
			 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x38, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x05, 0x00) + samrhdl +
	      raw_string(dom_m_len_lo, dom_m_len_hi, dom_mm_len_lo, dom_mm_len_hi, 0x40, 0x7B,
			 0x13, 0x00, dom_t_len_lo, dom_t_len_hi, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, dom_len_lo, dom_len_hi, 0x00) + dom + raw_string(0x00);

	send(socket:soc, data:req);
	r = smb_recv(socket:soc);
	if(strlen(r) < 88){
		return(FALSE);
	}
	#display(ord(r[88]), "\n");
  	_sid = "";
  	for(i=0; i<28; i=i+1)
	{
		_sid = _sid + raw_string(ord(r[88+i]));
		 #display(hex(ord(r[88+i])),  " ");
  	}
	#display("\n");
	return (_sid);
 }

 #------------------------------------------------------#
 # Opens a policy handle to a given domain              #
 #------------------------------------------------------#
 function SamrOpenDomain(soc, tid, uid, pipe, samrhdl, sid)
 {
 	#display("sid = ", strlen(sid), "\n");
	tid_hi = tid / 256;
	tid_lo = tid % 256;
	uid_hi = uid / 256;
	uid_lo = uid % 256;

	pipe_hi = pipe / 256;
	pipe_lo = pipe % 256;

 	len = 132 + strlen(sid);
	len_h = len / 256;
	len_l = len % 256;

	tdc = 48 + strlen(sid);
	tdc_l = tdc % 256;
	tdc_h = tdc / 256;

	bcc = tdc + 17;
	bcc_l = bcc % 256;
	bcc_h = bcc / 256;
	req = raw_string(0x00, 0x00,
 			 0x00, 0xA0, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
			 0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
			 g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x4C, 0x00, 0x00,
			 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
			 0x00, 0x4C, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26,
			 0x00, pipe_lo, pipe_hi, 0x5D, 0x00, 0x00, 0x5C, 0x00,
			 0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
			 0x5C, 0x00, 0x00, 0x00, 0x33, 0x00, 0x05, 0x00,
			 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x4C, 0x00,
			 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x34, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x07, 0x00) + samrhdl +
	      raw_string(0x00, 0x02, 0x00, 0x00) + sid;
	send(socket:soc, data:req);
	r = smb_recv(socket:soc);
	if(strlen(r) < 30){
		return(FALSE);
	}
 	#display(strlen(r),"\n");
	samrhdl = "";
	_len = strlen(r);
	_len = _len - 24;
	_z = 0;
	for(i=0; i<20; i=i+1)
 	{
		if(ord(r[i+_len]) == 0)_z = _z + 1;
		samrhdl = samrhdl + raw_string(ord(r[i+_len]));
		#display(hex(ord(r[i+_len])), " ");
	}
	#display("\n");
	#display("samhdl : ", strlen(samrhdl), "\n");
	if(_z == 20){
		return(NULL);
	}
 	return(samrhdl);
 }

 #------------------------------------------------------#
 # NetUserModalsGet - does not work yet		       #
 #------------------------------------------------------#
 function SamrQueryDomainInfo(soc, tid, uid, pipe, samrhdl, level)
 {
 	#display("sid = ", strlen(sid), "\n");
	tid_hi = tid / 256;
	tid_lo = tid % 256;
	uid_hi = uid / 256;
	uid_lo = uid % 256;

	pipe_hi = pipe / 256;
	pipe_lo = pipe % 256;

 	req = raw_string(0x00, 0x00,
 			 0x00, 0x82, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
			 0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
			 g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x2e, 0x00, 0x00,
			 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
			 0x00, 0x2e, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26,
			 0x00, pipe_lo, pipe_hi, 0x3f, 0x00, 0x00, 0x5C, 0x00,
			 0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
			 0x5C, 0x00, 0x00, 0x00, 0x45, 0x00, 0x05, 0x00,
			 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x2E, 0x00,
			 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x16, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x08, 0x00) + samrhdl +
	      raw_string(level % 256, level / 256);

	send(socket:soc, data:req);
	r = smb_recv(socket:soc);
	if(strlen(r) < 30){
		return(FALSE);
	}
	return r;
 }

 function SamrOpenBuiltin(soc, tid, uid, pipe, samrhdl)
 {
 	tid_hi = tid / 256;
	tid_lo = tid % 256;
	uid_hi = uid / 256;
	uid_lo = uid % 256;

	pipe_hi = pipe / 256;
	pipe_lo = pipe % 256;

	req = raw_string(0x00, 0x00,
 			 0x00, 0x94, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
			 0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
			 g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x40, 0x00, 0x00,
			 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
			 0x00, 0x40, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26,
			 0x00, pipe_lo, pipe_hi, 0x51, 0x00, 0x00, 0x5C, 0x00,
			 0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
			 0x5C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
			 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x40, 0x00,
			 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x28, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x07, 0x00) + samrhdl +
	      raw_string(0x80, 0x02, 0x00, 0x00, 0x01, 0x00,
			 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x05, 0x20, 0x00, 0x00, 0x00);

	send(socket:soc, data:req);
	r = smb_recv(socket:soc);
	builtinhdl = "";
	_len = strlen(r);
	_len = _len - 24;
	_z  = 0;
	for(i=0; i<20; i=i+1)
 	{
		if(ord(r[i+_len]) == 0){
			_z = _z + 1;
		}
		builtinhdl = builtinhdl + raw_string(ord(r[i+_len]));
		#display(hex(ord(r[i+_len])), " ");
 	}
	if(_z == 20){
		return(NULL);
	}
	#display("\n");
	#display("builtinhdl : ", strlen(builtinhdl), "\n");
	return(builtinhdl);
 }

 #--------------------------------------------------------#
 # Opens a policy handle to a given user                  #
 #--------------------------------------------------------#
 function SamrOpenUser(soc, uid, tid, pipe, samrhdl, rid)
 {
 	tid_hi = tid / 256;
	tid_lo = tid % 256;
	uid_hi = uid / 256;
	uid_lo = uid % 256;

	pipe_hi = pipe / 256;
	pipe_lo = pipe % 256;

	len = 176;
	len_hi = len / 256;
	len_lo = len % 256;

	req = raw_string(0x00, 0x00,
 			 0x00, 0x88, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
			 0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
			 g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x34, 0x00, 0x00,
			 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
			 0x00, 0x34, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26,
			 0x00, pipe_lo, pipe_hi, 0x45, 0x00, 0x00, 0x5C, 0x00,
			 0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
			 0x5C, 0x00, 0x00, 0x00, 0x33, 0x00, 0x05, 0x00,
			 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x34, 0x00,
			 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x1c, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x22, 0x00) + samrhdl +
	      raw_string(0x1B, 0x01, 0x02, 0x00) + rid;

	send(socket:soc, data:req);
	r = smb_recv(socket:soc);
	if(strlen(r) < 100){
		return(FALSE);
	}

	_usrhdl = "";
	_len = strlen(r);
	_len = _len - 24;
	#display("usrhdl = ");
	_z = 0;
	for(i=0; i<20; i=i+1)
	{
		if(ord(r[i+_len]) == 0){
			_z = _z + 1;
		}
		_usrhdl = _usrhdl + raw_string(ord(r[i+_len]));
		#display(hex(ord(r[i+_len])), " ");
 	}
 	if(_z == 20){
		return(NULL);
	}
	#display("\n");
	return(_usrhdl);
 }

 #----------------------------------------------------------#
 # Requests the list of groups to which the user belongs to #
 #----------------------------------------------------------#
 function SamrQueryUserGroups(soc, uid, tid, pipe, usrhdl)
 {
 	tid_hi = tid / 256;
	tid_lo = tid % 256;
	uid_hi = uid / 256;
	uid_lo = uid % 256;

	pipe_hi = pipe / 256;
	pipe_lo = pipe % 256;

	req = raw_string(0x00, 0x00,
 			 0x00, 0x80, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
			 0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
			 g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x2C, 0x00, 0x00,
			 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
			 0x00, 0x2C, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26,
			 0x00, pipe_lo, pipe_hi, 0x3D, 0x00, 0x00, 0x5C, 0x00,
			 0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
			 0x5C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
			 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x2C, 0x00,
			 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x14, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x27, 0x00) + usrhdl;
 	send(socket:soc, data:req);
	r = recv(socket:soc, length:4096);

 	num_lo = ord(r[88]);
	num_hi = ord(r[89]);

	num = num_hi * 256;
	num = num + num_lo;

	# Ok. Our user is in <num> groups. Let's decode their RID

	if(strlen(r) < 103){
		return(FALSE);
	}
	base = 100;
	rids = "";
	for(i=0; i<num; i=i+1)
	{
		g_rid = string(hex(ord(r[base+3])), "-",
		hex(ord(r[base+2])), "-",
		hex(ord(r[base+1])), "-",
		hex(ord(r[base])));

		base = base + 8;
		rids = rids + g_rid + string("\n");
 	}
	return(rids);
 }

 #------------------------------------------------------#
 # Queries information about a given user               #
 #------------------------------------------------------#
 function SamrQueryUserInfo(soc, uid, tid, pipe, usrhdl)
 {
	tid_hi = tid / 256;
	tid_lo = tid % 256;
	uid_hi = uid / 256;
	uid_lo = uid % 256;

	pipe_hi = pipe / 256;
	pipe_lo = pipe % 256;

	req = raw_string(0x00, 0x00,
 			 0x00, 0x82, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
			 0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
			 g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x2E, 0x00, 0x00,
			 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
			 0x00, 0x2E, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26,
			 0x00, pipe_lo, pipe_hi, 0x3F, 0x00, 0x00, 0x5C, 0x00,
			 0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
			 0x5C, 0x00, 0x00, 0x00, 0x33, 0x00, 0x05, 0x00,
			 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x2E, 0x00,
			 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x16, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x24, 0x00) + usrhdl +
	      raw_string(0x15, 0x00);

	send(socket:soc, data:req);
	r = smb_recv(socket:soc);

	return (r);
 }

 #-----------------------------------------------------------#
 # Requests the list of aliases to which the user belongs to #
 #-----------------------------------------------------------#
 function SamrQueryUserAliases(soc, uid, tid, pipe, usrhdl, sid, rid)
 {
 	tid_hi = tid / 256;
	tid_lo = tid % 256;
	uid_hi = uid / 256;
	uid_lo = uid % 256;

	pipe_hi = pipe / 256;
	pipe_lo = pipe % 256;

	subsid = "";

	for(i=0; i<20; i=i+1)
	{
		subsid = subsid + raw_string(ord(sid[8+i]));
		#display(hex(ord(sid[8+i])), " ");
	}
	#display("\n");

	req = raw_string(0x00, 0x00,
 			 0x00, 0xB0, 0xFF, 0x53, 0x4D, 0x42, 0x25, 0x00,
			 0x00, 0x00, 0x00, 0x18, 0x07, 0xC8, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, tid_lo, tid_hi, 0x00, 0x28, uid_lo, uid_hi,
			 g_mlo, g_mhi, 0x10, 0x00, 0x00, 0x5C, 0x00, 0x00,
			 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54,
			 0x00, 0x5C, 0x00, 0x54, 0x00, 0x02, 0x00, 0x26,
			 0x00, pipe_lo, pipe_hi, 0x6D, 0x00, 0x00, 0x5C, 0x00,
			 0x50, 0x00, 0x49, 0x00, 0x50, 0x00, 0x45, 0x00,
			 0x5C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00,
			 0x00, 0x03, 0x10, 0x00, 0x00, 0x00, 0x5C, 0x00,
			 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x44, 0x00,
			 0x00, 0x00, 0x00, 0x00, 0x10, 0x00) + usrhdl +
	      raw_string(0x01, 0x00, 0x00, 0x00, 0x88, 0x7C,
       	 		 0x13, 0x00, 0x01, 0x00, 0x00, 0x00, 0x98, 0x7C,
			 0x13, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01, 0x05,
			 0x00, 0x00) + subsid + rid;

	send(socket:soc, data:req);
	r = smb_recv(socket:soc);

	if(strlen(r) < 100)
	{
 		#display("=====>", strlen(r), "<====\n");
		return(FALSE);
	}

 	num_lo = ord(r[92]);
	num_hi = ord(r[93]);

	num = num_hi * 256;
	num = num + num_lo;
	#display("NUM EGAL : ", num, "\n");
	base = 96;
	rids = "";
	for(i=0; i<num; i=i+1)
 	{
		_rid = string(hex(ord(r[base+3])), "-",
  			      hex(ord(r[base+2])), "-",
			      hex(ord(r[base+1])), "-",
			      hex(ord(r[base])));
  		rids = rids + _rid + string("\n");
		base = base + 4;
	}
	return(rids);
 }

 function _ExtractTime(buffer, base)
 {
	if(strlen(buffer) < base + 8){
		return(FALSE);
	}

	return(string(hex(ord(buffer[base+7])), "-",
 		      hex(ord(buffer[base+6])), "-",
		      hex(ord(buffer[base+5])), "-",
		      hex(ord(buffer[base+4])), "-",
		      hex(ord(buffer[base+3])), "-",
		      hex(ord(buffer[base+2])), "-",
		      hex(ord(buffer[base+1])), "-",
		      hex(ord(buffer[base]))));
 }

 #------------------------------------------------------#
 # Decodes the informations received about a given usr  #
 # This function is not part of MSDN, hence the under-  #
 # score in front of it                                 #
 #------------------------------------------------------#
 function _SamrDecodeUserInfo(info, count, type)
 {
 	lim = strlen(info);

	if(strlen(info) < 100){
 		return(FALSE);
	}

	# Various times
 	logon = _ExtractTime(buffer:info, base:92);
	#display("Logon time : ", logon, "\n");

	set_kb_item(name:string("SMB/", type, "/", count, "/Info/LogonTime"),
 		    value:logon);

 	logoff = _ExtractTime(buffer:info, base:100);
	#display("Logoff time : ", logoff, "\n");
	set_kb_item(name:string("SMB/", type, "/", count, "/Info/LogoffTime"),
 		    value:logoff);

	if(strlen(info) < 116){
		return(FALSE);
	}

 	kickoff = _ExtractTime(buffer:info, base:108);
	#display("Kickoff time : ", kickoff, "\n");
	set_kb_item(name:string("SMB/", type, "/", count, "/Info/KickoffTime"),
 		    value:kickoff);

	base = 116;
	pass_last_set = _ExtractTime(buffer:info, base:116);

	if(strlen(info) < 124){
 		return(FALSE);
 	}

	#display("Pass last set : ", pass_last_set, "\n");
	set_kb_item(name:string("SMB/", type, "/", count, "/Info/PassLastSet"),
 		    value:pass_last_set);

	pass_can_change = _ExtractTime(buffer:info, base:124);
	#display("Pass can change : ", pass_can_change,"\n");
	set_kb_item(name:string("SMB/", type, "/", count, "/Info/PassCanChange"),
 		    value:pass_can_change);

	pass_must_change = _ExtractTime(buffer:info, base:132);

	#display("Pass must change : ", pass_must_change, "\n");
	set_kb_item(name:string("SMB/", type, "/", count, "/Info/PassMustChange"),
 		    value:pass_must_change);

	# ACB
 	if(strlen(info) < 260){
		return(FALSE);
 	}

	acb_lo = ord(info[260]);
	acb_hi = ord(info[261]);
	acb = acb_hi * 256;
	acb = acb + acb_lo;
	#display("ACB : ", hex(acb), "\n");

	set_kb_item(name:string("SMB/", type, "/", count, "/Info/ACB"), value:acb);

 	#if(acb & 0x01)display("  Account is disabled\n");
	#if(acb & 0x04)display("  Password not required\n");
	#if(acb & 0x10)display("  Normal account\n");
	#if(acb & 0x0200)display("  Password does not expire\n");
	#if(acb & 0x0400)display("  Account auto-locked\n");
	#if(acb & 0x0800)display("  Password can't be changed\n");

	#if(acb & 0x1000)display("  Smart card is required for interactive log on\n");
	#if(acb & 0x2000)display("  Account is trusted for delegation\n");
	#if(acb & 0x4000)display("  Account is sensitive an can not be delegated\n");
	#if(acb & 0x8000)display("  Use DES encryption type for this account\n");
 }

function unicode3( data ) {

  local_var data, len, ret, i;

  if( isnull( data ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#unicode3" );

  len = strlen( data );
  ret = raw_string(0, ord(data[0]));

  for( i = 1; i < len; i++ ) {
    ret += raw_string(0, ord(data[i]));
  }

  if( len & 1 ) {
    ret += raw_string(0x00, 0x00);
  } else {
    ret += raw_string(0x00, 0x00, 0x00, 0x00);
  }
  return ret;
}

function unicode4( data ) {

  local_var i, ret, len;

  if( isnull( data ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#unicode4" );

  len = strlen(data);
  ret = raw_string(0, ord(data[0]));

  for( i = 1; i < len; i++ ) {
    ret += raw_string(ord(data[i]),0);
  }

  if( len & 1 ) {
    ret += raw_string(0x00);
  }
  return ret;
}

# GetFileVersion() returns the version of the file.
function GetFileVersion( socket, uid, tid, fid ) {

  local_var i, fsize, data, off, tmp, version, v, len;

  if( isnull( socket ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#GetFileVersion" );
  if( isnull( uid ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#uid#-#GetFileVersion" );
  if( isnull( tid ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#tid#-#GetFileVersion" );
  if( isnull( fid ) ) set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#fid#-#GetFileVersion" );

  fsize = smb_get_file_size( socket:socket, uid:uid, tid:tid, fid:fid );
  if( fsize < 180224 ) {
    off = 0;
  } else {
    off = fsize - 180224;
  }

  for( i = 0; off < fsize; i++ ) {
    tmp = ReadAndX( socket:socket, uid:uid, tid:tid, fid:fid, count:16384, off:off );
    if( tmp ) {
      tmp = str_replace( find:raw_string(0), replace:"", string:tmp );
      data += tmp;
      version = strstr( data, "ProductVersion" );
      if( version ) {
        len = strlen( version );
        for( i = strlen( "ProductVersion" ); i < len; i++ ) {
          if( ( ord( version[i] ) < ord( "0" ) ||
                ord( version[i] ) > ord( "9" ) ) &&
                version[i] != "." ) {
            return v;
          } else {
            v += version[i];
          }
        }
      }
      off += 16384;
    }
  }
  return NULL;
}