import { analyzeFile } from "@/lib/scanner";

describe("Ruby/Rails ActiveRecord SQL injection (found via real-world OWASP railsgoat testing)", () => {
  it("flags a variable interpolated into an ActiveRecord .where() raw string", () => {
    const content = `
class UsersController < ApplicationController
  def update
    user = User.where("id = '#{params[:user][:id]}'")[0]
    user.save! if user
  end
end
`;
    const result = analyzeFile("app/controllers/users_controller.rb", content);
    const finding = result.indicators.find(i => i.id === "sql-injection");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("critical");
    expect(result.risk_score).toBe("CRITICAL");
  });

  it("does not flag a safe, parameterised ActiveRecord .where() call", () => {
    const content = `
class UsersController < ApplicationController
  def update
    user = User.where(id: params[:id]).first
    user.save! if user
  end
end
`;
    const result = analyzeFile("app/controllers/users_controller.rb", content);
    expect(result.indicators.some(i => i.id === "sql-injection")).toBe(false);
  });
});

describe("Rails strong-parameters bypass (found via real-world OWASP railsgoat testing)", () => {
  it("flags params.to_unsafe_h as mass assignment", () => {
    const content = `
class AdminController < ApplicationController
  def update_user
    user = User.find_by_id(params[:admin_id])
    user_params = params[:user].to_unsafe_h if params[:user].respond_to?(:to_unsafe_h)
    user.update(user_params)
  end
end
`;
    const result = analyzeFile("app/controllers/admin_controller.rb", content);
    expect(result.indicators.some(i => i.id === "mass-assignment")).toBe(true);
  });

  it("flags params.require(...).permit! as mass assignment", () => {
    const content = `
class UsersController < ApplicationController
  private

  def user_params
    params.require(:user).permit!
  end
end
`;
    const result = analyzeFile("app/controllers/users_controller.rb", content);
    expect(result.indicators.some(i => i.id === "mass-assignment")).toBe(true);
  });

  it("does not flag an explicit, allow-listed permit() call", () => {
    const content = `
class UsersController < ApplicationController
  private

  def user_params
    params.require(:user).permit(:email, :first_name, :last_name)
  end
end
`;
    const result = analyzeFile("app/controllers/users_controller.rb", content);
    expect(result.indicators.some(i => i.id === "mass-assignment")).toBe(false);
  });
});
