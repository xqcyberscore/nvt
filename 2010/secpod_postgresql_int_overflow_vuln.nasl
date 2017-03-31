###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_postgresql_int_overflow_vuln.nasl 5401 2017-02-23 09:46:07Z teissa $
#
# PostgreSQL Hash Table Integer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_solution = "Apply the patch,
  http://git.postgresql.org/gitweb?p=postgresql.git;a=commitdiff;h=64b057e6823655fb6c5d1f24a28f236b94dd6c54

  ******
  NOTE: Please ignore this warning if the patch is applied.
  ******";

tag_impact = "Successful exploitation could allow execution of specially-crafted sql query
  which once processed would lead to denial of service (postgresql daemon crash).
  Impact Level: Application";
tag_affected = "PostgreSQL version 8.4.1 and prior and 8.5 through 8.5alpha2";
tag_insight = "The flaw is due to an integer overflow error in 'src/backend/executor/nodeHash.c',
  when used to calculate size for the hashtable for joined relations.";
tag_summary = "The host is running PostgreSQL and is prone to integer overflow
  vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902139";
CPE = "cpe:/a:postgresql:postgresql";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5401 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-23 10:46:07 +0100 (Thu, 23 Feb 2017) $");
  script_tag(name:"creation_date", value:"2010-03-30 16:15:33 +0200 (Tue, 30 Mar 2010)");
  script_cve_id("CVE-2010-0733");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_name("PostgreSQL Hash Table Integer Overflow Vulnerability");


  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (c) 2010 SecPod");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("postgresql_detect.nasl");
  script_require_ports("Services/postgresql", 5432);
  script_require_keys("PostgreSQL/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=546621");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/03/16/10");
  script_xref(name : "URL" , value : "http://archives.postgresql.org/pgsql-bugs/2009-10/msg00310.php");
  script_xref(name : "URL" , value : "http://archives.postgresql.org/pgsql-bugs/2009-10/msg00289.php");
  script_xref(name : "URL" , value : "http://archives.postgresql.org/pgsql-bugs/2009-10/msg00287.php");
  script_xref(name : "URL" , value : "http://archives.postgresql.org/pgsql-bugs/2009-10/msg00277.php");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

port = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!port){
  port = 5432;
}

if(!get_tcp_port_state(port)){
  exit(0);
}

psqlver = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port);
if(isnull(psqlver)){
  exit(0);
}

if(version_is_less_equal(version:psqlver, test_version:"8.4.1") ||
   version_in_range(version:psqlver, test_version:"8.5", test_version2:"8.5.alpha2")){
  security_message(port:port);
}
