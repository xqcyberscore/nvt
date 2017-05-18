# OpenVAS Vulnerability Test
# $Id: securecrt_remote_overflow.nasl 6046 2017-04-28 09:02:54Z teissa $
# Description: SecureCRT SSH1 protocol version string overflow
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

tag_summary = "The remote host is using a vulnerable version of SecureCRT, a
SSH/Telnet client built for Microsoft Windows operation systems.

It has been reported that SecureCRT contain a remote buffer overflow
allowing an SSH server to execute arbitrary command via a specially
long SSH1 protocol version string.";

tag_solution = "Upgrade to SecureCRT 3.2.2, 3.3.4, 3.4.6, 4.1 or newer";

#  Ref: Kyuzo <ogl@SirDrinkalot.rm-f.net>

if(description)
{
 script_id(15822);
 script_version("$Revision: 6046 $");
 script_tag(name:"last_modification", value:"$Date: 2017-04-28 11:02:54 +0200 (Fri, 28 Apr 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2002-1059");
 script_bugtraq_id(5287);
 script_xref(name:"OSVDB", value:"4991");
 
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("SecureCRT SSH1 protocol version string overflow");
 


 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 script_family("Windows");
 script_dependencies("secpod_reg_enum.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

version = get_kb_item("SMB/Registry/HKLM/SOFTWARE/VanDyke/SecureCRT/License/Version");
if ( ! version ) version = get_kb_item("SMB/Registry/HKLM/SOFTWARE/VanDyke/SecureCRT/Evaluation License/Version");
if ( ! version ) exit(0);

if (egrep(pattern:"(2\.|3\.([01]|2[^.]|2\.1[^0-9]|3[^.]|3\.[1-3][^0-9]|4[^.]|4\.[1-5][^0-9])|4\.0 beta [12])", string:version))
  security_message(port);
