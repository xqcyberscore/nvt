# OpenVAS Vulnerability Test
# $Id: zone_alarm_local_dos.nasl 8087 2017-12-12 13:12:04Z teissa $
# Description: ZoneAlarm Pro local DoS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

tag_summary = "ZoneAlarm Pro firewall runs on this host.

This version contains a flaw that may allow a local denial of service. To
exploit this flaw, an attacker would need to temper with the files located in
%windir%/Internet Logs. An attacker may modify them and prevent ZoneAlarm
to start up properly.";

tag_solution = "Upgrade to the latest version of this software";

#  Ref: bipin gautam <visitbipin@yahoo.com>

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.14726");
 script_version("$Revision: 8087 $");
 script_cve_id("CVE-2004-2713");
 script_tag(name:"last_modification", value:"$Date: 2017-12-12 14:12:04 +0100 (Tue, 12 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_xref(name:"OSVDB", value:"9761");
 script_tag(name:"cvss_base", value:"1.9");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:P");
 script_name("ZoneAlarm Pro local DoS");
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 script_family("Firewalls");
 script_dependencies("secpod_reg_enum.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

## includes
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.14726";
SCRIPT_DESC = "ZoneAlarm Pro local DoS";

if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);

key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/ZoneAlarm Pro/DisplayName";
key2 = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/ZoneAlarm Pro/DisplayVersion";

if (get_kb_item (key))
{
 version = get_kb_item (key2);
 if (version)
 {
  set_kb_item (name:"zonealarm/version", value:version);

  ## build cpe and store it as host_detail
  cpe = build_cpe(value: version, exp:"^([0-9.]+)",base:"cpe:/a:zonelabs:zonealarm:");
  if(!isnull(cpe))
     register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

  if(ereg(pattern:"[1-4]\.|5\.0\.|5\.1\.", string:version))
  {
   security_message(0);
  }
 }
}
