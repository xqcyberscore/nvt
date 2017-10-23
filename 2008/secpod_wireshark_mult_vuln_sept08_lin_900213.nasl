##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wireshark_mult_vuln_sept08_lin_900213.nasl 7522 2017-10-20 08:19:44Z cfischer $
# Description: Wireshark Multiple Vulnerabilities - Sept-08 (Linux)
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900213";

if(description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 7522 $");
 script_tag(name:"last_modification", value:"$Date: 2017-10-20 10:19:44 +0200 (Fri, 20 Oct 2017) $");
 script_tag(name:"creation_date", value:"2008-09-10 17:51:23 +0200 (Wed, 10 Sep 2008)");
 script_bugtraq_id(31009);
 script_cve_id("CVE-2008-3146", "CVE-2008-3932", "CVE-2008-3933");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"executable_version");
 script_family("Denial of Service");
 script_name("Wireshark Multiple Vulnerabilities - Sept08 (Linux)");
 script_dependencies("gather-package-list.nasl", "gb_wireshark_detect_lin.nasl");
 script_mandatory_keys("Wireshark/Linux/Ver");
 script_xref(name:"URL", value:"http://secunia.com/advisories/31674");
 script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/2493");
 script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2008-05.html");

 script_tag(name:"summary", value:"Check for vulnerable version of Wireshark/Ethereal");
 script_tag(name:"affected", value:"Wireshark versions 1.0.2 and prior on Linux (All).");
 script_tag(name:"solution", value:"Upgrade to wireshark 1.0.3 or later.
http://www.wireshark.org/download.html");
 script_tag(name:"impact", value:"Successful exploitation could result in denial of service
condition or application crash by injecting a series of malformed
packets or by convincing the victim to read a malformed packet.
Impact Level : Application");
 exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

 report = string("\n Overview : The host is running Wireshark/Ethereal, which " +
                 "is prone to multiple\n vulnerabilities.\n" +
                 "\n        Vulnerability Insight:\n" +
                 "\n        Flaw(s) is/are due to,\n");
 vuln1 = string("       - infinite loop errors in the NCP dissector.\n");
 vuln2 = string("       - an error when uncompressing zlib-compressed packet data.\n");
 vuln3 = string("       - an error when reading a Tektronix .rf5 file.\n");

 foreach item (get_kb_list("ssh/login/rpms"))
 {
        if("ethereal" >< item)
	{
		if(egrep(pattern:"ethereal~0\.(9\.[7-9]|10\.(0?[0-9]|1[0-3]))($|[^.0-9])",
			 string:item))
                {
			security_message(data:string(report, vuln1));
                        exit(0);
                }
		else if(egrep(pattern:"ethereal~0\.(10\.14|99\.0)($|[^.0-9])", string:item))
		{
			security_message(data:string(report, vuln1, vuln2));
			exit(0);
		}
        }

	else if("wireshark" >< item)
	{
		if(egrep(pattern:"wireshark~0\.99\.[1-5]($|[^.0-9])", string:item))
                {
			security_message(data:string(report, vuln1, vuln2));
                        exit(0);
                }
		else if(egrep(pattern:"wireshark~(0\.99\.[6-9]|1\.0\.[0-2])($|[^.0-9])",
			      string:item))
		{
			security_message(data:string(report, vuln1, vuln2, vuln3));
                        exit(0);
                }
        }
 }

 sock = ssh_login_or_reuse_connection();
 if(!sock){
	exit(0);
 }

 etherealVer = ssh_cmd(socket:sock, cmd:"ethereal -v", timeout:120);
 ssh_close_connection();
 if("Compiled" >< etherealVer)
 {
	if(egrep(pattern:"ethereal 0\.(9\.[7-9]|10\.(0?[0-9]|1[0-3]))$",
          	 string:etherealVer))
	{
		security_message(data:string(report, vuln1));
 	}
	else if(egrep(pattern:"ethereal 0\.(10\.14|99\.0)$", string:etherealVer))
	{
		security_message(data:string(report, vuln1, vuln2));
                exit(0);
        }
 }

ver = get_app_version(cpe:"cpe:/a:wireshark:wireshark", nvt:SCRIPT_OID);

if(egrep(pattern:"wireshark 0\.99\.[1-5]$", string:ver))
{
  security_message(data:string(report, vuln1, vuln2));
} else if(egrep(pattern:"(0\.99\.[6-9]|1\.0\.[0-2])$", string:ver)) {
  security_message(data:string(report, vuln1, vuln2, vuln3));
}
