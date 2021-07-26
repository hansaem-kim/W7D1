class UsersController < ApplicationController
    before_action :ensure_logged_out, only: [:new, :create]
    before_action :ensure_logged_in, only: [:index, :show]
    
    def new
        @user = User.new
        render :new
    end

    def create
        @user = User.new(user_params)
        if user.save
            login(@user)
            redirect_to user_url(@user)
        else
            render :new
        end
    end

    private
    def user_params
        params.require(:user).permit(:user_name, :password)
    end
end