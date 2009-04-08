# RestAuth
module RestAuth
  def self.included(base)
    base.write_inheritable_attribute :actions_table, [] #actions_table用于存放set_ations配置的角色权限信息
    base.extend ClassMethods
    base.send :include, InstanceMethods
  end

  # 扩展Controller的类方法
  module ClassMethods    
    
    # 对action的访问进行配置
    # 参数: 
    #   role : 角色名称，符号或字符串。例如 :guest, :user 等
    #   opts : 哈希,一组角色权限的定义配置
    #       相关键：
    #       postfix : 字符串，角色相对应方法后缀名，默认为角色名称
    #       only : 数组,指明角色所能使用的action
    #       except : 数组,指明角色所不能使用的action
    #       rule : 符号或过程对象,判断所请求的用户是否是当前角色的依据
    # 例如：
    # set_actions :guest,:only=>[:new,:create]
    # set_actions :user,:except=>[:new,:create],:postfix=>'member',:rule=>:logged_in?
    #
    # 配置规则的优先级
    #   角色之间的关系可能存在以下几类：
    #      1. 角色之间完全独立，例如：role1有访问action1的权力;role2有访问action2的权力
    #      2. 角色之间存在
    #   配置按照自上而下排定优先级，访问用户的角色根据不符合rule规则的上一个角色来确定。
    #   在进行配置时，权力越高的角色应放置在最后，例如
    #   set_actions :guest
    #   set_actions :user,:rule=>:logged_in?
    #   set_actions :my,:rule=>my?
    #   set_actions :admin,:rule=>admin?

    def set_actions(role,opts={})
      opts[:postfix]||= role===String ? role : role.to_s 
      read_inheritable_attribute(:actions_table) << [role,opts]
    end
  end  
  
  module InstanceMethods
    # 重写method_missing
    # 当用户根据七种方法访问资源时，根据当前用户的角色进行重定向。
    # 例如: guest用户访问index方法，如果controller中没有定义index方法，则寻找index_guest方法
    def method_missing(method,*arg,&block)
      methods = ['index','new','edit','update','create','show','destroy']
      if methods.include?(method)
        role = get_role(self.class.read_inheritable_attribute(:actions_table))
        if role_allow?(role,method)
          self.action_name = method + '_'+role.last[:postfix]
          send self.action_name,*arg          
          return
        end
      end
      super(method.to_sym,*arg,&block)
    end
    
  private
  
    # 获得当前用户角色
    # 对于当前角色的选定有以下规则：
    #  1. 对于:rule为空的角色，系统作为默认角色
    #  2. 如果有多个角色的:rule为空，系统将最后一个角色作为默认角色
    #  3. 如果一个用户同时满足多个角色，系统将最后满足的角色作为用户的角色
    def get_role(actions_table)
      roles = []
      default_role = :default
      actions_table.each do |row|
        opts = row.last
        opts[:rule].blank? ? (default_role = row) : (roles << row if run_rule(opts[:rule]))
      end
      roles.empty? ? default_role : roles.last
    end
    
    # 判断当前用户是否有权限使用当前method
    def role_allow?(role,method)
      return false if role == :default
      opts = role.last
      opts[:only] && !(opts[:only].include?(method) || opts[:only].include?(method.to_sym)) ? false : true
    end
    
    # 执行角色中定义的规则
    def run_rule(rule)
      Symbol === rule ? self.method(rule).call : rule.call(self)
    end     
  end
end


  

    
 
