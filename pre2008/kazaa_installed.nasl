# OpenVAS Vulnerability Test
# $Id: kazaa_installed.nasl 5452 2017-03-01 08:53:44Z cfi $
# Description: Kazaa is installed
#
# Authors:
# Xue Yong Zhi <xueyong@udel.edu>
#
# Copyright:
# Copyright (C) 2003 Xue Yong Zhi
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

tag_summary = "The remote host is using Kazaa - a p2p software, which may not 
be suitable for a business environment.";

tag_solution = "Uninstall this software";

if(description)
{
 script_id(11426);
 script_version("$Revision: 5452 $");
 script_tag(name:"last_modification", value:"$Date: 2017-03-01 09:53:44 +0100 (Wed, 01 Mar 2017) $");
 script_tag(name:"creation_date", value:"2006-03-26 18:10:09 +0200 (Sun, 26 Mar 2006)");
 script_bugtraq_id(3135, 4121, 4122, 5317, 6435, 6747);
 script_cve_id("CVE-2002-0314", "CVE-2002-0315");  
 
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 name = "Kazaa is installed";

 script_name(name);
 



 summary = "Determines if Kazaa is installed";

 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
 
 script_copyright("This script is Copyright (C) 2003 Xue Yong Zhi");
 family = "Peer-To-Peer File Sharing";
 script_family(family);
 
 script_dependencies("secpod_reg_enum.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",
		     "SMB/domain","SMB/transport");
 script_mandatory_keys("SMB/WindowsVersion");

 script_require_ports(139, 445);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}


include("smb_nt.inc");


rootfile = registry_get_sz(key:"SOFTWARE\Kazaa\CloudLoad",
 item:"ExeDir");
if(rootfile)
{
 security_message(get_kb_item("SMB/transport"));
}

