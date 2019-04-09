# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.


# @brief This function is used by basic policy tests. The silence value is set in
# compliance_tests.nasl. If you start the test within a standard policy like
# IT-Grundschutz, the results are silent by default. If you start the basic
# policy test by themselves, they are verbose.
#
# @param text the text to log
#
function policy_logging(text) {

  local_var verbose, text;

  verbose = get_kb_item("Compliance/verbose");
  if(verbose) {
    log_message(data:text, port:0);
  }
}

function policy_add_oid() {
  set_kb_item(name:"PolicyOIDs", value:get_script_oid());
}

function policy_set_compliance(compliant) {

  local_var compliant;

  set_kb_item(name:get_script_oid() + "/COMPLIANT", value:compliant);
}

function policy_set_kb(val) {

  local_var val;

  # nb: save as string, because value can be "0", which would lead to not set the kb_entry
  set_kb_item(name:get_script_oid() + "/RESULT", value:chomp(string(val)));
}

function policy_set_kb_hcu(id, val) {

  local_var id, val;

  # nb: save as string, because value can be "0", which would lead to not set the kb_entry
  set_kb_item(name:get_script_oid() + "/RESULT/" + id, value:chomp(string(val)));
}

function policy_set_dval(dval) {

  local_var dval;

  # nb: save as string, because value can be "0", which would lead to not set the kb_entry
  set_kb_item(name:get_script_oid() + "/DEFAULT", value:chomp(string(dval)));
}

function policy_fixtext(fixtext) {

  local_var fixtext;

  fixtext = str_replace(string:fixtext, find:'\n', replace:' ');
  set_kb_item(name:get_script_oid() + "/FIX", value:fixtext);
}

function policy_control_name(title) {

  local_var title;

  title = str_replace(string:title, find:'\n', replace:' ');
  set_kb_item(name:get_script_oid() + "/NAME", value:title);
}

function policy_logging_registry(type, key, item, value) {

  local_var type, key, item, value;

  policy_logging(text:'Registry value ' + type + '\\' + key + '!' + item + ' is set to: ' + value);
}

function rsop_securitysettingsboolean(select, keyname) {

  # nb: rsop only delivers results for domain admins

  local_var select, keyname;
  local_var infos, handle, query, res, splitRes, returnValue;

  infos = kb_smb_wmi_connectinfo();
  if(!infos)
    exit(0);

  handle = wmi_connect(host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"], ns:'root\\rsop\\computer');
  if(!handle) {
    policy_logging(text:'WMI Connect to host failed.');
    policy_set_kb(val:'error');
    exit(0);
  }

  query = "SELECT " + select + " FROM RSOP_SecuritySettingBoolean WHERE KeyName = '" + keyname + "' AND precedence = '1'";
  res = wmi_query_rsop(wmi_handle:handle, query:query);
  wmi_close(wmi_handle:handle);

  splitRes = split(res, sep:"|", keep:FALSE);
  if(max_index(splitRes) < 4)
    return('');

  returnValue = splitRes[4];
  return(string(returnValue));
}

function rsop_securitysettingsnumeric(select,keyname) {

  # nb: rsop only delivers results for domain admins

  local_var select, keyname;
  local_var infos, handle, query, res, splitRes, returnValue;

  infos = kb_smb_wmi_connectinfo();
  if(!infos)
    exit(0);

  handle = wmi_connect(host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"], ns:'root\\rsop\\computer');
  if(!handle) {
    policy_logging(text:'WMI Connect to host failed.');
    policy_set_kb(val:'error');
    exit(0);
  }

  query = "SELECT " + select + " FROM RSOP_SecuritySettingNumeric WHERE KeyName = '" + keyname + "' AND precedence = '1'";
  res = wmi_query_rsop(wmi_handle:handle, query:query);
  wmi_close(wmi_handle:handle);

  splitRes = split(res, sep:"|", keep:FALSE);
  if(max_index(splitRes) < 4)
    return('');

  returnValue = splitRes[4];
  return(string(returnValue));
}

function rsop_userprivilegeright(select, keyname) {

  # nb: rsop only delivers results for domain admins

  local_var select, keyname;
  local_var infos, handle, query, res, splitRes, accountList, MaxIndexAccountList, i, returnValue;

  infos = kb_smb_wmi_connectinfo();
  if(!infos)
    exit(0);

  handle = wmi_connect(host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"], ns:'root\\rsop\\computer');
  if(!handle) {
    policy_logging(text:'WMI Connect to host failed.');
    policy_set_kb(val:'error');
    exit(0);
  }

  query = "SELECT " + select + " FROM RSOP_UserPrivilegeRight WHERE UserRight = '" + keyname + "'";
  res = wmi_query_rsop(wmi_handle:handle, query:query);
  wmi_close(wmi_handle:handle);
  if(res == '')
    return "None";

  splitRes = split(res, keep:FALSE);
  accountList = split(splitRes[1], sep:"|", keep:FALSE);
  MaxIndexAccountList = max_index(accountList);
  for(i=0; i<MaxIndexAccountList-2; i++) {
    returnValue += accountList[i];
    if(i<MaxIndexAccountList-3) {
      returnValue += ', ';
    }
  }

  return(string(returnValue));
}

function win32_useraccount(select, name) {

  local_var select, name;
  local_var infos, handle, query, res;

  infos = kb_smb_wmi_connectinfo();
  if(!infos)
    exit(0);

  handle = wmi_connect(host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"]);
  if(!handle) {
    policy_logging(text:'WMI Connect to host failed.');
    policy_set_kb(val:'error');
    exit(0);
  }

  query = "SELECT " + select + " FROM Win32_UserAccount WHERE Name = '" + name + "'";
  res = wmi_query(wmi_handle:handle, query:query);
  wmi_close(wmi_handle:handle);

  return(res);
}

# @brief Checks for a package whether it is installed and if so, which version
#
# @param package The package to check the existence / version
# @param maintainer The package maintainer (RPM or DEB)
#
# @return A string with the version or NULL if not installed on host
#
function get_package_version(package) {

  local_var package;
  if(!package) {
    set_kb_item( name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#package_version#-#package" );
    return;
  }

  if(get_kb_item('ssh/login/rpms')) {
    packages_string = get_kb_item('ssh/login/rpms');
    packages_list = split(packages_string, sep:';', keep:FALSE);
    foreach pak (packages_list) {
      package_split = split(pak, sep:'~', keep:FALSE);
      name = package_split[0];
      version = package_split[1];
      if(name == package) {
        return version;
      }
    }
  } else if(get_kb_item('ssh/login/packages')) {
    packages_string = get_kb_item('ssh/login/packages');
    packages_list = split(packages_string, keep:FALSE);
    foreach line (packages_list) {
      if(line =~ "^ii") {
        line_split = ereg_replace(string:line, pattern:'\\s+', replace:'|');
        packages_info = split(line_split, sep:'|', keep:FALSE);
        name = packages_info[1];
        version = packages_info[2];
        if(name == package) {
          return version;
        }
      }
    }
  }
  return;
}

# @brief Tries to find a GRUB bootloader config file on the host.
#        Searches for grub.conf, grub.cfg or menu.lst in directories
#        /boot/grub/ or /boot/grub2/.
#
# @return Filepath if config file found or NULL if not found
#         (maybe because of denied read permisisons)
#
function get_grub_config_file() {

  local_var grub_config_files, grub_config_dirs, dir, file, config_file;

  grub_config_files = make_list('grub.conf', 'grub.cfg', 'menu.lst');
  grub_config_dirs = make_list('/boot/grub/', '/boot/grub2/');

  foreach dir (grub_config_dirs) {
    foreach file (grub_config_files) {
      config_file = find_file(file_name:file, file_path:dir);
      if(config_file)
        return config_file[0];
    }
  }
  return;
}

# @brief sends a ssh_cmd and filters errors in return values.
#
# @param socket the socket for the ssh command
# @param cmd the bash command
#
# @return return of the command or NULL if file not found or
#         other error occurred
#
function ssh_cmd_without_errors(socket, cmd) {

  local_var socket, cmd, ret;

  ret = ssh_cmd(socket:socket, cmd:cmd, return_errors:FALSE);

  if('No such file or directory' >< ret || 'command not found' >< ret)
    return;

  return(ret);
}

# @brief checks the file permissions, gid and uid with stat command
#        on a linux host
#
# @param file the file to check
# @param sock socket for the ssh command
#
# @return an array with keys permissions, gid and uid
#
function linux_file_permissions(file, socket) {

  local_var socket, file;
  local_var stat_cmd, stat, return_array, access, gid, uid, permissions;

  if(!socket) {
    set_kb_item(name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#linux_file_permissions#-#socket");
    return;
  }

  if(!file) {
    set_kb_item(name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#linux_file_permissions#-#file");
    return;
  }

  stat_cmd = 'stat ' + file;
  stat = ssh_cmd_without_errors(socket:socket, cmd:stat_cmd);
  if(stat && ('permission denied' >!< tolower(stat))) {
    return_array = make_list();
    access = eregmatch(string:stat, pattern:'(Access:.+Uid.+Gid.+\\))');
    gid = eregmatch(string:access[0], pattern:'Gid: \\((.+)\\)');
    uid = eregmatch(string:access[0], pattern:'Uid: \\(([^\\)]*)\\)');
    permissions = eregmatch(string:access[0], pattern:'Access: \\(([0-9]+)');

    return_array['permissions'] = permissions[1];
    return_array['gid'] = str_replace(string:gid[1], find:' ', replace:'');
    return_array['uid'] = str_replace(string:uid[1], find:' ', replace:'');

    return (return_array);
  }
  return;
}

# @brief check if a service is enabled on a Linux host.
#        Uses systemctl is-enabled, chkconfig --list and
#        at last search for service in /etc/rc*.d files
#
# @param service the service to search for
# @param socket socket for the ssh command
#
# @return TRUE if service is enabled, NULL if not
#
function linux_service_is_enabled(service, socket) {

  local_var service, socket;
  local_var systemctl_cmd, systemctl, chkconfig_cmd, chkconfig;
  local_var ls_grep_cmd, ls_grep, enabled;

  if(!socket) {
    set_kb_item(name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#linux_file_permissions#-#socket");
    return;
  }

  if(!service) {
    set_kb_item(name:"nvt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#linux_file_permissions#-#service");
    return;
  }

  systemctl_cmd = 'systemctl is-enabled ' + service;
  systemctl = ssh_cmd_without_errors(socket:socket, cmd:systemctl_cmd);
  if('enabled' >< systemctl) {
    return TRUE;
  }

  chkconfig_cmd = 'chkconfig --list ' + service;
  chkconfig = ssh_cmd_without_errors(socket:socket, cmd:chkconfig_cmd);
  if('2:on' >< chkconfig && '3:on' >< chkconfig && '4:on' >< chkconfig && '5:on' >< chkconfig) {
    return TRUE;
  }

  ls_grep_cmd = 'ls /etc/rc*.d | grep ' + service;
  ls_grep = ssh_cmd_without_errors(socket:socket, cmd:ls_grep_cmd);
  enabled = eregmatch(string:ls_grep, pattern:'[\\^S][^\n\r]*');
  if(enabled)
    return TRUE;

  return;
}

# @brief check if a service is enabled on a Linux host.
#        Uses systemctl is-enabled, chkconfig --list and
#        at last search for service in /etc/rc*.d files
#
# @param service the service to search for
# @param socket socket for the ssh command
#
# @return TRUE if service is enabled, NULL if not
#
function check_permission_denied(value, file) {

  local_var value, file, ret;

  if('permission denied' >< tolower(value)) {
    ret = 'No permission to read in file "' + file + '".';
    return(ret);
  }
  return;
}