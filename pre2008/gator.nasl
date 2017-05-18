# OpenVAS Vulnerability Test
# $Id: gator.nasl 6040 2017-04-27 09:02:38Z teissa $
# Description: Gator/GAIN Spyware Installed
#
# Authors:
# Jeff Adams <jeffrey.adams@hqda.army.mil>
#
# Copyright:
# Copyright (C) 2003 Jeff Adams
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

tag_summary = "The remote host has Gator/GAIN Spyware Installed. Gator tracks the sites that 
users visit and forwards that data back to the company's servers. Gator sells 
the use of this information to advertisers. It also lets companies launch a 
pop-up ad when users visit various Web sites. This software is not suitable 
for a business environment.";

tag_solution = "Uninstall the software";

if(description)
{
 script_id(11883);
 script_version("$Revision: 6040 $");
 script_tag(name:"last_modification", value:"$Date: 2017-04-27 11:02:38 +0200 (Thu, 27 Apr 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

 name = "Gator/GAIN Spyware Installed";

 script_name(name);
 


 
 summary = "Determines if Gator Spyware is installed";

 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
 
 script_copyright("This script is Copyright (C) 2003 Jeff Adams");
 family = "Windows";
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

rootfile = registry_get_sz(key:"SOFTWARE\Gator.com\Gator\dyn", item:"AppExe");
if(rootfile)
{
 security_message(get_kb_item("SMB/transport"));
}
