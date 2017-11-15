###############################################################################
# OpenVAS Vulnerability Test
# $Id: policy_registry.nasl 7753 2017-11-14 10:57:07Z jschulte $
#
# Windows Registry Check
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
#
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105988");
  script_version("$Revision: 7753 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-14 11:57:07 +0100 (Tue, 14 Nov 2017) $");
  script_tag(name:"creation_date", value:"2015-05-22 12:17:31 +0700 (Fri, 22 May 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Windows Registry Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_add_preference(name:"Policy registry file", type:"file", value:"");

  script_tag(name:"summary", value:"Checks the presens of specified Registry keys
  and values.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");

reglist = script_get_preference("Policy registry file");
if (!reglist)
  exit(0);

reglist = script_get_preference_file_content("Policy registry file");
if (!reglist)
  exit(0);

lines = split(reglist, keep:0);
line_count = max_index(lines);

if (line_count == 1 && lines[0] == "Present|Hive|Key|Value|ValueType|ValueContent")
  exit(0);	# Just header is present

function exit_cleanly() {
  set_kb_item(name:"policy/registry_no_timeout", value: TRUE);

  exit(0);
}

set_kb_item(name:"policy/registry_started", value:TRUE);

for (i=1; i<line_count; i++) {
  line = lines[i];
  # Check structure of line
  if (!eregmatch(pattern:"(TRUE|FALSE)\|HKLM\|([a-zA-Z0-9\\]+)\|.*\|(REG_DWORD|REG_SZ|REG_BINARY)\|.*",
                 string:line) && !eregmatch(pattern:"(TRUE|FALSE)\|HKLM\|([a-zA-Z0-9\\]+)", string:line)) {
    if (eregmatch(pattern:"^$", string:line))
      break;
    set_kb_item(name:"policy/registry_err", value:'Invalid line: ' + line);
  }
  else {
    val = split(line, sep:"|", keep:0);
    present = tolower(val[0]);
    hive = val[1];
    key = val[2];
    if (max_index(val) == 6) {
      value = val[3];
      type = val[4];
      content = val[5];
    }

    # Just check if registry key exists
    if (max_index(val) < 6) {
      key_exists = registry_key_exists(key:key);
      if (((present == "true") && key_exists) ||
          ((present == "false") && !key_exists))
        set_kb_item(name:"policy/registry_ok", value:hive + '\\' + key + ' | ' + present);
      else
        if (((present == "true") && !key_exists) ||
            ((present == "false") && key_exists))
          set_kb_item(name:"policy/registry_fail", value:hive + '\\' + key + ' | ' + present);
          replace_kb_item(name:"policy/registry_fail_exists", value:TRUE);
    }
    # Check as well the content
    else {
      if (type == "REG_DWORD")
        reg_content = registry_get_dword(key:key, item:value);
      else if (type == "REG_SZ")
        reg_content = registry_get_sz(key:key, item:value);
      else if (type == "REG_BINARY")
        reg_content = registry_get_binary(key:key, item:value);
      if (reg_content == content && present == "true" ||
        reg_content != content && present == "false") {
        set_kb_item(name:"policy/registry_ok", value:hive + '\\' + key + '\\' + value + ' | ' + present + ' | ' +
                  content + ' | ' + reg_content);
        replace_kb_item(name:"policy/registry_ok_exists", value:TRUE);
      }
      else {
        if (reg_content == content && present == "false" ||
          reg_content != content && present == "true") {
          set_kb_item(name:"policy/registry_fail", value:hive + '\\' + key + '\\' + value + ' | ' + present + ' | ' +
                        content + ' | ' + reg_content);
          replace_kb_item(name:"policy/registry_fail_exists", value:TRUE);
        }
      }
    }
  }
}

exit_cleanly();
