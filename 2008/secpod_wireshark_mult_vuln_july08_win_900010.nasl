##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wireshark_mult_vuln_july08_win_900010.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: Wireshark Multiple Vulnerabilities - July08 (Windows)
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

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.900010");
 script_version("$Revision: 9349 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
 script_bugtraq_id(28485);
 script_cve_id("CVE-2008-1561", "CVE-2008-1562", "CVE-2008-1563");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"registry");
 script_family("General");
 script_name("Wireshark Multiple Vulnerabilities - July08 (Windows)");
 script_dependencies("secpod_reg_enum.nasl");
 script_mandatory_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 script_tag(name:"insight", value: "The flaws exist due to errors in GSM SMS dissector, PANA and KISMET
dissectors, RTMPT dissector, RMI dissector, and in syslog dissector.");
 script_tag(name:"solution", value: "Upgrade to wireshark to 1.0.1 or later.
http://www.wireshark.org/download.html");
 script_tag(name:"summary", value: "The host is running Wireshark/Ethereal, which is prone to multiple
vulnerabilities.");
 script_tag(name:"affected", value: "Wireshark versions prior to 1.0.1 on Windows (All).

Quick Fix : Disable the following dissectors,
GSM SMS, PANA, KISMET, RTMPT, and RMI");
 script_tag(name:"impact", value: "Successful exploitation could result in application crash,
disclose of system memory, and an incomplete syslog encapsulated
packets.
Impact Level : SYSTEM");
 exit(0);
}


 include("smb_nt.inc");

 if(!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }

 etherealVer = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
			       "\Uninstall\Ethereal", item:"DisplayVersion");
 if(etherealVer)
 {
	etherealVer = ereg_replace(pattern:"Ethereal (.*)", replace:"\1",
                            	   string:etherealVer);
	if(ereg(pattern:"^(0\.(10\.([0-9]|1[0-4])|99\.0))$",
		string:etherealVer))
	{
		security_message(0);
		exit(0);
	}
 }

 wiresharkVer = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
			        "\Uninstall\Wireshark", item:"DisplayVersion");
 if(!wiresharkVer){
	exit(0);
 }

 if(ereg(pattern:"^(0\.99\.[0-9]|1\.0\.0)$", string:wiresharkVer)){
	security_message(0);
 }
