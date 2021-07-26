# == Schema Information
#
# Table name: users
#
#  id              :bigint           not null, primary key
#  user_name       :string           not null
#  password_digest :string           not null
#  session_token   :string           not null
#  created_at      :datetime         not null
#  updated_at      :datetime         not null
#
class User < ApplicationRecord
    validates :user_name, :session_token, presence: true, uniqueness: true
    validates :password_digest, presence: true #V

    after_initialize :ensure_session_token #A

    attr_reader :password

    def ensure_session_token #E
        self.session_token ||= User.generate_session_token
    end

    def generate_session_token #G
        SecureRandom.urlsafe_base64
    end

    def reset_session_token! #R
        self.session_token = User.generate_session_token
        self.save!
        self.session_token
    end

    def password=(password) #P
        @password = password
        self.password_digest = BCrypt::Password.create(password)
    end

    def is_password?(password) #I
        BCrypt::Password.new(self.password_digest).is_password?(password)
    end

    def self.find_by_credentials(user_name, password) #F
        user = User.find_by(user_name: user_name)

        if user && user.is_password?(password)
            user
        else
            nil
        end
    end


end
