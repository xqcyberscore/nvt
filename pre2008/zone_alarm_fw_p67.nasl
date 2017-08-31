# OpenVAS Vulnerability Test
# $Id: zone_alarm_fw_p67.nasl 6532 2017-07-05 07:42:05Z cfischer $
# Description: ZoneAlarm Personal Firewall port 67 flaw
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

tag_summary = "ZoneAlarm firewall runs on this host.

This version contains a flaw that may allow a remote attacker to bypass 
the ruleset. 
The issue is due to ZoneAlarm not monitoring and alerting UDP traffic with a 
source port of 67. 

This allows an attacker to bypass the firewall to reach protected hosts without 
setting off warnings on the firewall.";

tag_solution = "Upgrade at least to version 2.1.25";

#  Ref: Wally Whacker <whacker@hackerwhacker.com>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14660");
  script_version("$Revision: 6532 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-05 09:42:05 +0200 (Wed, 05 Jul 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1137);
  script_cve_id("CVE-2000-0339");  
  script_xref(name:"OSVDB", value:"1294");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("ZoneAlarm Personal Firewall port 67 flaw");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Firewalls");
  script_dependencies("zone_alarm_local_dos.nasl");
  script_mandatory_keys("zonealarm/version");

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

zaversion = get_kb_item ("zonealarm/version");
if (!zaversion) exit (0);

if(ereg(pattern:"[0-1]\.|2\.0|2\.1\.([0-9]|1[0-9]|2[0-4])[^0-9]", string:zaversion))
{
 security_message(0);
}
