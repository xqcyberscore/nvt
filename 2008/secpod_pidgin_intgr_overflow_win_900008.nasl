##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_pidgin_intgr_overflow_win_900008.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: Pidgin MSN SLP Message Integer Overflow Vulnerabilities (Windows)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

tag_impact = "Remote attacker can execute arbitrary code by sending
	specially crafted SLP message with the privilege of a user.
 Impact Level : SYSTEM";

tag_solution = "Upgrade to Pidgin Version 2.4.3,
 http://www.pidgin.im/download/";


tag_summary = "The host is running Pidgin, which is prone to integer
 overflow vulnerability.";

tag_affected = "- Pidgin Version prior to 2.4.3 on Windows (All).";
tag_insight = "The flaw is due to errors in the msn_slplink_process_msg
 	function in libpurple/protocols/msnp9/slplink.c and
 	libpurple/protocols/msn/slplink.c files, which fails to perform
	adequate boundary checks on user-supplied data.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.900008");
 script_version("$Revision: 9349 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
 script_bugtraq_id(29956);
 script_cve_id("CVE-2008-2927");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
 script_family("General");
 script_name("Pidgin MSN SLP Message Integer Overflow Vulnerabilities (Windows)");
 script_dependencies("secpod_reg_enum.nasl");
 script_mandatory_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 script_tag(name : "affected" , value : tag_affected);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "impact" , value : tag_impact);
 script_xref(name : "URL" , value : "http://www.pidgin.im/news/security/?id=24");
 exit(0);
}


 include("smb_nt.inc");

 if(!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }

 pidginVer = registry_get_sz(item:"DisplayVersion",
	     key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Pidgin");

 if(egrep(pattern:"^([01]\..*|2\.([0-3](\..*)?|4(\.[0-2])?))$", string:pidginVer)){
 	security_message(0);
 }
