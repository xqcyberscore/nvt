##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_db2_8_udb_mult_vuln_lin_900216.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: IBM DB2 Universal Database Multiple Vulnerabilities - Sept08 (Linux)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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

tag_impact = "Remote exploitation could allow attackers to bypass security
        restrictions, cause a denial of service or gain elevated privileges.
 Impact Level : Application";

tag_solution = "Update to Fixpak 17 or later.
 ftp://ftp.software.ibm.com/ps/products/db2/fixes/

 *****
 NOTE : Ignore this warning, if above mentioned patch is already applied.
 *****";

tag_affected = "IBM DB2 version 8 prior to Fixpak 17 on Linux (All).";

tag_insight = "The flaws exist due to unspecified errors in processing of
        - CONNECT/ATTACH requests, 
        - DB2FMP process and DB2JDS service.";


tag_summary = "The host is running DB2 Database Server, which is prone to multiple
 vulnerabilities.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.900216");
 script_version("$Revision: 9349 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-09-25 09:10:39 +0200 (Thu, 25 Sep 2008)");
 script_bugtraq_id(31058);
 script_cve_id("CVE-2008-2154", "CVE-2008-3958", "CVE-2008-3960");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
 script_family("Denial of Service");
 script_name("IBM DB2 Universal Database Multiple Vulnerabilities - Sept08 (Linux)");
 script_dependencies("gather-package-list.nasl", "secpod_ibm_db2_detect_linux_900217.nasl");
 script_mandatory_keys("Linux/IBM_db2/Ver", "Linux/IBM_db2/FixPack", "ssh/login/uname");
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "affected" , value : tag_affected);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "impact" , value : tag_impact);
 script_xref(name : "URL" , value : "http://secunia.com/advisories/31787/");
 script_xref(name : "URL" , value : "http://www.frsirt.com/english/advisories/2008/2517");
 script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2008/Sep/1020826.html");
 script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg1JR29274");
 exit(0);
}


 if("Linux" >!< get_kb_item("ssh/login/uname")){
        exit(0);
 }

 if(egrep(pattern:"^8\.[0-2]\..*", string:get_kb_item("Linux/IBM_db2/Ver"))){
 	security_message(0);
 }
