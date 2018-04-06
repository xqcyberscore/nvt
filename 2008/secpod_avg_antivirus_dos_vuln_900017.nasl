##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_avg_antivirus_dos_vuln_900017.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: AVG Anti-Virus UPX Processing Denial of Service Vulnerability
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

tag_impact = "Remote attackers with successful exploitation could deny
        the service by causing the scanning engine to crash.
 Impact Level : Application.";

tag_solution = "Upgrade to latest AVG Anti-Virus 8.0.156 or later.
 http://www.grisoft.com/ww.download-trial";

tag_affected = "AVG Anti-Virus prior to 8.0.156 on Windows (All).";

tag_insight = "The flaw is caused to a divide by zero error in file parsing engine
        while handling UPX compressed executables.";


tag_summary = "The remote host is installed with AVG AntiVirus, which is prone
 to denial of service vulnerability.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.900017");
 script_version("$Revision: 9349 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
 script_cve_id("CVE-2008-3373");
 script_bugtraq_id(30417);
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
 script_family("Denial of Service");
 script_name("AVG Anti-Virus UPX Processing Denial of Service Vulnerability");
 script_dependencies("secpod_reg_enum.nasl");
 script_mandatory_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 script_xref(name : "URL" , value : "http://www.grisoft.com/ww.94247");
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "affected" , value : tag_affected);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "impact" , value : tag_impact);
 exit(0);
}


 include("smb_nt.inc");

 if(!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }

 if(!registry_key_exists(key:"SOFTWARE\AVG")){
	exit(0);
 }

 for (i=1; i<=8; i++)
 {
 	avgVer = registry_get_sz(key:"SOFTWARE\AVG\AVG" + i + "\LinkScanner\Prevalence",
			 	 item:"CODEVER");
	if(avgVer)
	{
		# Grep AVG Anti-Virus version < 8.0.156
 		if(egrep(pattern:"^([0-7]\..*|8\.0(\.([0-9]?[0-9]|1[0-4]" +
				 "[0-9]|15[0-5])))$", string:avgVer)){
			security_message(0);
		}
		exit(0);
	}
 }
