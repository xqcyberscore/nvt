# OpenVAS Vulnerability Test
# $Id: tftp_permissions_hp_ignite_ux.nasl 6046 2017-04-28 09:02:54Z teissa $
# Description: TFTP directory permissions (HP Ignite-UX)
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

if(description)
{
   script_oid("1.3.6.1.4.1.25623.1.0.19510");
   script_version("$Revision: 6046 $");
   script_tag(name:"last_modification", value:"$Date: 2017-04-28 11:02:54 +0200 (Fri, 28 Apr 2017) $");
   script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
   script_bugtraq_id(14571);
   script_cve_id("CVE-2004-0952");
   script_tag(name:"cvss_base", value:"6.4");
   script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");

   script_name("TFTP directory permissions (HP Ignite-UX)");

   script_category(ACT_DESTRUCTIVE_ATTACK); # Intrusive
   script_copyright("This NASL script is Copyright 2005 Corsaire Limited.");
   script_xref(name : "URL" , value : "http://www.corsaire.com/advisories/c041123-002.txt");
   script_family("General");
   script_dependencies("tftpd_backdoor.nasl");
   script_require_udp_ports("Services/udp/tftp");
	
   script_tag(name : "solution" , value : "Upgrade to a version of the Ignite-UX application that does not exhibit
   this behaviour. If it is not required, disable or uninstall the TFTP server. 
   Otherwise restrict access to trusted sources only.");
   script_tag(name : "summary" , value : "The remote host has a vulnerable version of the HP Ignite-UX application 
   installed that exposes a world-writeable directory to anonymous TFTP access.");

   script_tag(name:"qod_type", value:"remote_vul");

 
   exit(0);
}



############## declarations ################




port = get_kb_item('Services/udp/tftp');
if ( ! port ) exit(0);
if ( get_kb_item("tftp/" + port + "/backdoor") ) exit(0);



############## script ################

include("tftp.inc");

# initialise test
file_name='/var/opt/ignite/openvas_tftp_test_'+rand();
if(tftp_put(port:port,path:file_name)) {
   security_message(port:port,proto:"udp");
   exit(0);
}

exit(99);
