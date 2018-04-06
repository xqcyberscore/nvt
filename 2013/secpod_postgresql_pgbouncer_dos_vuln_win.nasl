###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_postgresql_pgbouncer_dos_vuln_win.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# PostgreSQL PgBouncer Denial of Service Vulnerability (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow remote attackers to cause the application
  to crash by creating a denial of service condition.
  Impact Level: Application";

tag_affected = "PostgreSQL PgBouncer Pooler version 1.5.2 and prior on Windows";
tag_insight = "An error exists within the 'add_database' function in objects.c in the
  pgbouncer pooler when adding new databases with an an overly large name.";
tag_solution = "Upgrade to PostgreSQL PgBouncer Pooler version 1.5.3 or later,
  For updates refer to http://wiki.postgresql.org/wiki/PgBouncer";
tag_summary = "This host is installed with PostgreSQL PgBouncer pooler and is
  prone to denial of service vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903102");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2012-4575");
  script_bugtraq_id(56371);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-01-25 11:24:17 +0530 (Fri, 25 Jan 2013)");
  script_name("PostgreSQL PgBouncer Denial of Service Vulnerability (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51128");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/79751");
  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2012/11/02/8");
  script_xref(name : "URL" , value : "http://git.postgresql.org/gitweb/?p=pgbouncer.git;a=commit;h=4b92112b820830b30cd7bc91bef3dd8f35305525");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_postgresql_detect_win.nasl");
  script_mandatory_keys("PostgreSQL/Win/Ver");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initialization
pgsqlVer = "";
pgkey = "";
pgbounVer = "";

## Get PostgreSQL version from KB
pgsqlVer = get_kb_item("PostgreSQL/Win/Ver");
if(!pgsqlVer) exit(0);

## Get PostgreSQL PgBouncer Pooler version from Registry
pgkey = "SOFTWARE\EnterpriseDB\PgBouncer";
if(!registry_key_exists(key:pgkey)){
  exit(0);
}

# Get version
pgbounVer = registry_get_sz(key:pgkey, item:"Version");
if(!pgbounVer) exit(0);

if(pgbounVer =~ "-")
  pgbounVer = ereg_replace(pattern:"-", string:pgbounVer, replace:".");

## Check for PgBouncer version less than 1.5.3
if(version_is_less(version:pgbounVer, test_version:"1.5.3")){
  security_message(0);
}
