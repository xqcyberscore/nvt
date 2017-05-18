# OpenVAS Vulnerability Test
# $Id: tftp_files_cisco_ios_ca.nasl 6056 2017-05-02 09:02:50Z teissa $
# Description: TFTP file detection (Cisco IOS CA)
#
# Authors:
# Martin O'Neal of Corsaire (http://www.corsaire.com)
#
# Copyright:
# Copyright (C) 2005 Corsaire Limited
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

# The script will test whether the remote host has one of a number of sensitive  
# files present on the tftp server
#
# DISCLAIMER
# The information contained within this script is supplied "as-is" with 
# no warranties or guarantees of fitness of use or otherwise. Corsaire 
# accepts no responsibility for any damage caused by the use or misuse of 
# this information.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17341");
  script_version("$Revision: 6056 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-02 11:02:50 +0200 (Tue, 02 May 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("TFTP file detection (Cisco IOS CA)");
  script_category(ACT_ATTACK);
  script_copyright("This NASL script is Copyright 2005 Corsaire Limited.");
  script_family("General");
  script_dependencies("tftpd_detect.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);
 
  script_tag(name : "summary" , value : "The remote host has a TFTP server installed that is serving one or more 
  sensitive Cisco IOS Certificate Authority (CA) files.");
  script_tag(name : "insight" , value : "These files potentially include the private key for the CA so should be considered 
  extremely sensitive and should not be exposed to unnecessary scrutiny.");
  script_tag(name : "solution" , value : "If it is not required, disable the TFTP server. Otherwise restrict access to
  trusted sources only.");

  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("tftp.inc");
include("network_func.inc");

# initialise variables
local_var request_data;
local_var file_name;
local_var file_postfix;
local_var postfix_list;
local_var ca_name;
local_var detected_files;
local_var description;
postfix_list=make_list('.pub','.crl','.prv','.ser','#6101CA.cer','.p12');

## Check for tftp service
port = get_kb_item("Services/udp/tftp");
if(!port){
  port = 69;
}

## Check Port State
if(!check_udp_port_status(dport:port)){
  exit(0);
}

# step through first nine certificate files
for(i=1;i<10;i++)
{
	# initialise variables
	file_name=raw_string(ord(i),'.cnm');
	
	# request numeric certificate file
	if(request_data=tftp_get(port:port,path:file_name))
	{
		# initialise variables
		ca_name=eregmatch(string:request_data,pattern:'subjectname_str = cn=(.+),ou=');
		
		# check if cn is present in certificate file
		if(ca_name[1])
		{
			# add filename to response
			detected_files=raw_string(detected_files,file_name,"\n");
			
			# step through files
			foreach file_postfix (postfix_list)
			{
				# initialise variables
				file_name=raw_string(ca_name[1],file_postfix);

				# request certificate file
				if(request_data=tftp_get(port:port,path:file_name))
				{
					# add filename to response
					detected_files=raw_string(detected_files,file_name,"\n");
				}
			}
			
			break;
		}
	}
}

# check if any files were detected
if(detected_files)
{
	description= "The filenames detected are:

" +detected_files;
	security_message(data:description,port:port,proto:"udp");
	exit(0);
}

exit(99);
